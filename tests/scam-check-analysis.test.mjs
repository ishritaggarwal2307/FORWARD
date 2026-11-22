import assert from 'node:assert/strict'
import test from 'node:test'
import { analyzeMessage } from '../src/features/scam-check/analysis/analyzeText.ts'
import { analyzeUrl } from '../src/features/scam-check/analysis/analyzeUrl.ts'
import {
  analyzeExtractedScreenshotText,
  analyzeScreenshot,
} from '../src/features/scam-check/analysis/analyzeScreenshot.ts'

test('direct OTP request is high concern and includes explainable evidence', () => {
  const result = analyzeMessage('Your account is locked. Send your verification code immediately.')

  assert.equal(result.inputMode, 'message')
  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request' && finding.strength === 'strong'))
  assert.ok(result.findings.every((finding) => finding.evidence))
})

test('OTP safety advice does not trigger an authentication request', () => {
  const result = analyzeMessage('Never share your OTP with anyone.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'credentials-request'))
})

test('account suspension is a weak warning without a sensitive detail request', () => {
  const result = analyzeMessage('Your bank account will be blocked unless you contact support.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'account-access-threat' && finding.strength === 'weak'))
})

test('KYC expiration alone remains informational', () => {
  const result = analyzeMessage('Your KYC verification expires on 30 June. Please visit a branch if you have questions.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'kyc-expiration-mentioned' && finding.strength === 'informational'))
})

test('KYC expiration with an unexpected verification link raises warning signs, not high concern', () => {
  const result = analyzeMessage('Your KYC verification has expired. Verify your account at https://example.com/verify.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'kyc-expiration-mentioned'))
  assert.ok(result.findings.some((finding) => finding.id === 'verification-link-with-request'))
})

test('account threat, expired KYC, and urgent banking update form a strong combination', () => {
  const result = analyzeMessage('Your bank account will be blocked because your KYC has expired. Update your banking information immediately.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'account-access-threat'))
  assert.ok(result.findings.some((finding) => finding.id === 'kyc-expiration-mentioned'))
  assert.ok(result.findings.some((finding) => finding.id === 'banking-details-request'))
  assert.ok(result.findings.some((finding) => finding.id === 'account-verification-combination' && finding.strength === 'strong'))
})

test('legitimate KYC reminder is not elevated to high concern', () => {
  const result = analyzeMessage('A reminder: please complete your KYC verification at your next branch visit. No online action is required.')

  assert.notEqual(result.riskLevel, 'high-concern')
  assert.ok(!result.findings.some((finding) => finding.id === 'account-verification-combination'))
})

test('routine bank account notification is not elevated by account terminology alone', () => {
  const result = analyzeMessage('Your monthly account statement is ready to view in the bank app.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
})

test('ordinary conversation with urgency and verification wording is not enough to trigger findings', () => {
  const result = analyzeMessage('I urgently need to verify the meeting time before we leave for dinner.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
})

test('quoted scam text is treated as an example, not an active request', () => {
  const result = analyzeMessage('The suspicious text said: “Send your OTP immediately or your account will be blocked.”')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
})

test('negated sensitive information request is not treated as an instruction', () => {
  const result = analyzeMessage('Do not provide your password or verification code to anyone.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'credentials-request'))
})

test('a direct OTP request remains high concern alongside weak findings', () => {
  const result = analyzeMessage('Your account may be locked. Send your OTP immediately.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'account-access-threat'))
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
})

test('ordinary message wording does not claim the content is safe', () => {
  const result = analyzeMessage('Your appointment is confirmed for Friday afternoon.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.match(result.summary, /does not confirm.*safe/i)
})

test('empty message input is inconclusive', () => {
  assert.equal(analyzeMessage('  ').riskLevel, 'inconclusive')
})

test('malformed URL input is inconclusive', () => {
  assert.equal(analyzeUrl('not a url').riskLevel, 'inconclusive')
})

test('URL review explains embedded credentials', () => {
  const result = analyzeUrl('https://user:secret@example.com/login')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.equal(result.findings[0].id, 'embedded-credentials')
  assert.match(result.limitations[0], /does not visit the site/i)
})

test('HTTP-only URL is an informational observation and does not elevate risk', () => {
  const clean = analyzeUrl('https://example.com')
  const http = analyzeUrl('http://example.com')

  assert.equal(clean.riskLevel, 'no-obvious-warning-signs')
  assert.match(clean.summary, /does not verify.*safe/i)
  assert.equal(http.riskLevel, 'no-obvious-warning-signs')
  assert.equal(http.findings[0].id, 'unencrypted-connection')
  assert.equal(http.findings[0].strength, 'informational')
})

test('valid IPv4 and IPv6 literals are identified as weak observations', () => {
  const ipv4 = analyzeUrl('https://192.0.2.10/login')
  const ipv6 = analyzeUrl('https://[2001:db8::1]/login')

  assert.equal(ipv4.riskLevel, 'some-warning-signs')
  assert.equal(ipv4.findings.find((finding) => finding.id === 'ip-address-host')?.strength, 'weak')
  assert.equal(ipv6.riskLevel, 'some-warning-signs')
  assert.match(ipv6.findings.find((finding) => finding.id === 'ip-address-host')?.title ?? '', /IPv6/)
})

test('invalid IPv4 addresses are rejected instead of classified as IP hosts', () => {
  const result = analyzeUrl('https://256.1.1.1/login')

  assert.equal(result.riskLevel, 'inconclusive')
  assert.ok(!result.findings.some((finding) => finding.id === 'ip-address-host'))
})

test('ordinary HTTPS domain has no structural warning findings', () => {
  const result = analyzeUrl('https://www.example.com/account')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
})

test('domain-like subdomain explains the estimated registered destination', () => {
  const result = analyzeUrl('https://paypal.com.fake-example.org/login')
  const finding = result.findings.find((item) => item.id === 'domain-like-subdomain')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.match(finding?.explanation ?? '', /fake-example\.org/)
  assert.match(finding?.explanation ?? '', /does not prove.*malicious/i)
})

test('excessive subdomain depth is a weak finding, not proof of malicious intent', () => {
  const result = analyzeUrl('https://one.two.three.four.five.example.org/login')
  const finding = result.findings.find((item) => item.id === 'many-domain-levels')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.equal(finding?.strength, 'weak')
})

test('explicit Punycode is weak while a normal internationalized hostname is informational', () => {
  const punycode = analyzeUrl('https://xn--bcher-kva.example/path')
  const international = analyzeUrl('https://bücher.example/path')

  assert.equal(punycode.riskLevel, 'some-warning-signs')
  assert.ok(punycode.findings.some((finding) => finding.id === 'punycode-host' && finding.strength === 'weak'))
  assert.equal(international.riskLevel, 'no-obvious-warning-signs')
  assert.ok(international.findings.some((finding) => finding.id === 'internationalized-host' && finding.strength === 'informational'))
})

test('ordinary encoded paths are informational and encoded separators are weak', () => {
  const ordinary = analyzeUrl('https://example.com/search?q=hello%20world')
  const suspicious = analyzeUrl('https://example.com/a%2Fb')

  assert.equal(ordinary.riskLevel, 'no-obvious-warning-signs')
  assert.ok(ordinary.findings.some((finding) => finding.id === 'encoded-url-path' && finding.strength === 'informational'))
  assert.equal(suspicious.riskLevel, 'some-warning-signs')
  assert.ok(suspicious.findings.some((finding) => finding.id === 'suspicious-url-encoding' && finding.strength === 'weak'))
})

test('percent-encoded host characters are reported when the browser parser accepts them', () => {
  const result = analyzeUrl('https://%62ank.example/login')

  assert.ok(['inconclusive', 'some-warning-signs'].includes(result.riskLevel))
  if (result.riskLevel !== 'inconclusive') {
    assert.ok(result.findings.some((finding) => finding.id === 'encoded-hostname' && finding.strength === 'strong'))
  }
})

test('embedded credentials are strong and combine with an independent warning for high concern', () => {
  const credentialsOnly = analyzeUrl('https://user:secret@example.com/login')
  const combined = analyzeUrl('https://user:secret@192.0.2.10/login')

  assert.equal(credentialsOnly.riskLevel, 'some-warning-signs')
  assert.equal(credentialsOnly.findings.find((finding) => finding.id === 'embedded-credentials')?.strength, 'strong')
  assert.equal(combined.riskLevel, 'high-concern')
  assert.ok(combined.findings.some((finding) => finding.id === 'ip-address-host'))
})

test('common URL shorteners are informational and are never expanded', () => {
  const result = analyzeUrl('https://bit.ly/abc123')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'shortened-url' && finding.strength === 'informational'))
})

test('malformed and unsupported scheme URLs are inconclusive', () => {
  assert.equal(analyzeUrl('https://[not-ipv6]/path').riskLevel, 'inconclusive')
  assert.equal(analyzeUrl('javascript:alert(1)').riskLevel, 'inconclusive')
})

test('insufficient screenshot OCR text returns inconclusive', () => {
  assert.equal(analyzeExtractedScreenshotText('Hi, click.').riskLevel, 'inconclusive')
})

test('readable screenshot OCR text uses message checks and adds OCR limitations', () => {
  const result = analyzeExtractedScreenshotText('Please send your one-time code immediately to restore access to your account.')

  assert.equal(result.inputMode, 'screenshot')
  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.limitations.some((limitation) => /English OCR/.test(limitation)))
})

test('screenshot OCR receives the in-memory file, reports progress, and terminates its worker', async () => {
  const image = new File(['image bytes'], 'message.png', { type: 'image/png' })
  const progress = []
  let receivedImage
  let terminated = false
  const result = await analyzeScreenshot(image, (value) => progress.push(value), { workerFactory: async (logger) => {
    logger({ status: 'recognizing text', progress: 1.4 })
    return {
      recognize: async (input) => {
        receivedImage = input
        return { data: { text: 'Please send your one-time code immediately to restore access to your account.' } }
      },
      terminate: async () => { terminated = true },
    }
  } })

  assert.equal(receivedImage, image)
  assert.equal(result.riskLevel, 'high-concern')
  assert.deepEqual(progress, [{ stage: 'recognizing', progress: 1 }])
  assert.equal(terminated, true)
})

test('unreadable screenshot OCR returns inconclusive and releases its worker', async () => {
  const image = new File(['image bytes'], 'blank.png', { type: 'image/png' })
  let terminated = false
  const result = await analyzeScreenshot(image, () => {}, { workerFactory: async () => ({
    recognize: async () => ({ data: { text: '   ' } }),
    terminate: async () => { terminated = true },
  }) })

  assert.equal(result.riskLevel, 'inconclusive')
  assert.equal(terminated, true)
})

test('OCR setup failure returns inconclusive instead of fabricated results', async () => {
  const image = new File(['image bytes'], 'message.png', { type: 'image/png' })
  const result = await analyzeScreenshot(image, () => {}, { workerFactory: async () => {
    throw new Error('OCR resources unavailable')
  } })

  assert.equal(result.riskLevel, 'inconclusive')
  assert.match(result.summary, /could not be read/i)
})

test('unsupported and oversized image files are rejected before OCR starts', async () => {
  let workerStarted = false
  const workerFactory = async () => {
    workerStarted = true
    throw new Error('Should not be called')
  }
  const wrongType = new File(['text'], 'note.txt', { type: 'text/plain' })
  const tooLarge = new File([new Uint8Array(10 * 1024 * 1024 + 1)], 'large.png', { type: 'image/png' })

  assert.equal((await analyzeScreenshot(wrongType, () => {}, { workerFactory })).riskLevel, 'inconclusive')
  assert.equal((await analyzeScreenshot(tooLarge, () => {}, { workerFactory })).riskLevel, 'inconclusive')
  assert.equal(workerStarted, false)
})

test('cancelled screenshot analysis terminates its worker', async () => {
  const image = new File(['image bytes'], 'message.png', { type: 'image/png' })
  const controller = new AbortController()
  let terminated = false
  const pendingRecognition = new Promise(() => {})
  const resultPromise = analyzeScreenshot(image, () => {}, {
    signal: controller.signal,
    workerFactory: async () => ({
      recognize: async () => pendingRecognition,
      terminate: async () => {
        terminated = true
      },
    }),
  })

  await new Promise((resolve) => setImmediate(resolve))
  controller.abort()
  const result = await resultPromise

  assert.equal(result.riskLevel, 'inconclusive')
  assert.match(result.summary, /stopped/i)
  assert.equal(terminated, true)
})
