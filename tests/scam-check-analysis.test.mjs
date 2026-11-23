import assert from 'node:assert/strict'
import test from 'node:test'
import { analyzeMessage } from '../src/features/scam-check/analysis/analyzeText.ts'
import { analyzeUrl } from '../src/features/scam-check/analysis/analyzeUrl.ts'
import {
  analyzeExtractedScreenshotText,
  analyzeScreenshot,
} from '../src/features/scam-check/analysis/analyzeScreenshot.ts'

const readableImageInspector = async () => ({ width: 800, height: 600 })

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

test('gift card purchase and code-sharing request from a manager is high concern', () => {
  const result = analyzeMessage('Your manager needs you to buy gift cards and send the codes.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'gift-card-purchase-request' && finding.strength === 'weak'))
  assert.ok(result.findings.some((finding) => finding.id === 'gift-card-value-request' && finding.strength === 'strong'))
  assert.ok(result.findings.some((finding) => finding.id === 'gift-card-request-combination' && finding.highConcernTrigger === 'contextual-combination'))
})

test('gift card purchase request without authority or urgency is a warning, not high concern', () => {
  const result = analyzeMessage('Please buy gift cards for the office thank-you event.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'gift-card-purchase-request'))
  assert.ok(!result.findings.some((finding) => finding.id === 'gift-card-request-combination'))
})

test('a workplace gift-card purchase without value transfer is not high concern', () => {
  const result = analyzeMessage('Your manager asked me to buy gift cards for the office event.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'gift-card-purchase-request'))
  assert.ok(!result.findings.some((finding) => finding.id === 'gift-card-request-combination'))
})

test('request for gift card photos identifies transferable value', () => {
  const result = analyzeMessage('Please send a photo of the gift cards and their redemption codes.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'gift-card-value-request' && finding.strength === 'strong'))
})

test('urgent gift card code transfer is high concern', () => {
  const result = analyzeMessage('Buy gift cards immediately and send me the redemption codes right away.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'contextual-urgency'))
  assert.ok(result.findings.some((finding) => finding.id === 'gift-card-request-combination'))
})

test('a secret gift-card code transfer is high concern', () => {
  const result = analyzeMessage('Please buy gift cards and send the redemption codes while keeping this request confidential.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'gift-card-value-request'))
  assert.ok(result.findings.some((finding) => finding.id === 'gift-card-request-combination'))
})

test('educational and ordinary gift card discussions do not trigger scam findings', () => {
  const educational = analyzeMessage('Scam awareness: scammers may ask you to buy gift cards and share the codes.')
  const ordinary = analyzeMessage('I bought gift cards for my nieces last weekend.')
  const generalDiscussion = analyzeMessage('Gift cards are popular birthday presents and easy to wrap.')

  assert.equal(educational.riskLevel, 'no-obvious-warning-signs')
  assert.equal(educational.findings.length, 0)
  assert.equal(ordinary.riskLevel, 'no-obvious-warning-signs')
  assert.equal(ordinary.findings.length, 0)
  assert.equal(generalDiscussion.riskLevel, 'no-obvious-warning-signs')
  assert.equal(generalDiscussion.findings.length, 0)
})

test('unexpected prize selection with a registration request is a weak warning', () => {
  const result = analyzeMessage('You have been selected for a prize draw; register to learn more.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'unexpected-prize-selection' && finding.strength === 'weak'))
})

test('general promotional prize announcement is not automatically suspicious', () => {
  const result = analyzeMessage('Join our summer prize draw. Register today for a chance to win a gift card.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'unexpected-prize-selection'))
})

test('prize processing fee request creates a high-concern combination', () => {
  const result = analyzeMessage('Pay a processing fee to claim your lottery winnings.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'prize-claim-payment-combination'))
})

test('banking information requested to claim a prize is high concern', () => {
  const result = analyzeMessage('You won a prize. Update your banking information to receive your reward.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'banking-details-request'))
  assert.ok(result.findings.some((finding) => finding.id === 'prize-claim-payment-combination'))
})

test('routine bank branch instruction is not a warning', () => {
  const result = analyzeMessage('Please update your banking information at your nearest branch.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'banking-details-request'))
})

test('banking information requested through an unexpected link remains a warning', () => {
  const result = analyzeMessage('Please update your banking information using this link https://bank.example/update.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'banking-details-request'))
  assert.ok(result.findings.some((finding) => finding.id === 'verification-link-with-request'))
})

test('urgency with a banking information request raises warning signs', () => {
  const result = analyzeMessage('Update your banking information immediately.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'banking-details-request'))
  assert.ok(result.findings.some((finding) => finding.id === 'contextual-urgency'))
})

test('account threat with an offline branch instruction does not become a strong banking combination', () => {
  const result = analyzeMessage('Your account will be blocked. Update your banking information at your nearest branch.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'account-access-threat'))
  assert.ok(!result.findings.some((finding) => finding.id === 'account-verification-combination'))
})

test('routine account maintenance and a trusted-app update are not high concern', () => {
  const result = analyzeMessage('Your account will be temporarily locked for scheduled maintenance. Update your banking information in our secure app when service resumes.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'account-access-threat'))
  assert.ok(result.findings.some((finding) => finding.id === 'banking-details-request'))
  assert.ok(!result.findings.some((finding) => finding.id === 'account-verification-combination'))
})

test('unrelated account-threat and banking-update sentences do not combine into high concern', () => {
  const result = analyzeMessage('Your bank account will be blocked next month. Separately, update banking information for payroll using the company app.')

  assert.notEqual(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'account-access-threat'))
  assert.ok(result.findings.some((finding) => finding.id === 'banking-details-request'))
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

test('inline quoted scam wording in a discussion is not treated as an active request', () => {
  const result = analyzeMessage('The text "send your OTP immediately" looks suspicious.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
})

test('a raw suspicious message pasted inside quotation marks is still analyzed', () => {
  const result = analyzeMessage('"Your account is locked. Send your OTP immediately."')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
  assert.ok(result.findings.every((finding) => finding.evidence))
})

test('negated sensitive information request is not treated as an instruction', () => {
  const result = analyzeMessage('Do not provide your password or verification code to anyone.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'credentials-request'))
})

test('a negation suppresses its instruction but not a later active OTP request', () => {
  const result = analyzeMessage('Never share your OTP with strangers, but send your OTP to this support agent now.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
  assert.match(result.findings.find((finding) => finding.id === 'credentials-request')?.evidence ?? '', /send your OTP/i)
})

test('a negation about links does not suppress a separate OTP request', () => {
  const result = analyzeMessage('Do not click suspicious links. Share your OTP with the support agent.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
})

test('a negated link instruction does not suppress an active request in the same sentence', () => {
  const result = analyzeMessage('Do not click the link, and send your OTP to this support agent.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
})

test('educational warnings about gift-card code requests remain non-alarming', () => {
  const result = analyzeMessage('Be careful of messages asking you to buy gift cards and send the codes.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
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
  assert.equal(analyzeExtractedScreenshotText('   ').riskLevel, 'inconclusive')
  assert.equal(analyzeExtractedScreenshotText('').riskLevel, 'inconclusive')
})

test('readable screenshot OCR text uses message checks and adds OCR limitations', () => {
  const result = analyzeExtractedScreenshotText('Please send your one-time code immediately to restore access to your account.')

  assert.equal(result.inputMode, 'screenshot')
  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.limitations.some((limitation) => /English OCR/.test(limitation)))
  assert.ok(result.limitations.some((limitation) => /not a scam-risk score/i.test(limitation)))
})

test('low-confidence and garbled OCR extraction are inconclusive', () => {
  const readableText = 'Please send your one-time code immediately to restore access to your account.'

  assert.equal(analyzeExtractedScreenshotText(readableText, 20).riskLevel, 'inconclusive')
  assert.equal(analyzeExtractedScreenshotText('@@@ ### %%% !!! &&& *** ??? ###', 90).riskLevel, 'inconclusive')
})

test('screenshot OCR receives the in-memory file, reports progress, and terminates its worker', async () => {
  const image = new File(['image bytes'], 'message.png', { type: 'image/png' })
  const progress = []
  let receivedImage
  let terminated = false
  const result = await analyzeScreenshot(image, (value) => progress.push(value), { imageInspector: readableImageInspector, workerFactory: async (logger) => {
    logger({ status: 'recognizing text', progress: 1.4 })
    return {
      recognize: async (input) => {
        receivedImage = input
        return { data: { text: 'Please send your one-time code immediately to restore access to your account.', confidence: 92 } }
      },
      terminate: async () => { terminated = true },
    }
  } })

  assert.equal(receivedImage, image)
  assert.equal(result.riskLevel, 'high-concern')
  assert.deepEqual(progress, [{ stage: 'recognizing', progress: 1 }])
  assert.equal(terminated, true)
  assert.ok(!Object.values(result).includes(image))
})

test('unreadable screenshot OCR returns inconclusive and releases its worker', async () => {
  const image = new File(['image bytes'], 'blank.png', { type: 'image/png' })
  let terminated = false
  const result = await analyzeScreenshot(image, () => {}, { imageInspector: readableImageInspector, workerFactory: async () => ({
    recognize: async () => ({ data: { text: '   ' } }),
    terminate: async () => { terminated = true },
  }) })

  assert.equal(result.riskLevel, 'inconclusive')
  assert.equal(terminated, true)
})

test('OCR setup failure returns inconclusive instead of fabricated results', async () => {
  const image = new File(['image bytes'], 'message.png', { type: 'image/png' })
  const result = await analyzeScreenshot(image, () => {}, { imageInspector: readableImageInspector, workerFactory: async () => {
    throw new Error('OCR resources unavailable')
  } })

  assert.equal(result.riskLevel, 'inconclusive')
  assert.match(result.summary, /could not be read/i)
})

test('OCR recognition errors terminate the worker and return inconclusive', async () => {
  const image = new File(['image bytes'], 'message.png', { type: 'image/png' })
  let terminated = false
  const result = await analyzeScreenshot(image, () => {}, { imageInspector: readableImageInspector, workerFactory: async () => ({
    recognize: async () => { throw new Error('Recognition failed') },
    terminate: async () => { terminated = true },
  }) })

  assert.equal(result.riskLevel, 'inconclusive')
  assert.equal(terminated, true)
})

test('unsupported and oversized image files are rejected before OCR starts', async () => {
  let workerStarted = false
  const workerFactory = async () => {
    workerStarted = true
    throw new Error('Should not be called')
  }
  const wrongType = new File(['text'], 'note.txt', { type: 'text/plain' })
  const tooLarge = new File([new Uint8Array(10 * 1024 * 1024 + 1)], 'large.png', { type: 'image/png' })

  assert.equal((await analyzeScreenshot(wrongType, () => {}, { imageInspector: readableImageInspector, workerFactory })).riskLevel, 'inconclusive')
  assert.equal((await analyzeScreenshot(tooLarge, () => {}, { imageInspector: readableImageInspector, workerFactory })).riskLevel, 'inconclusive')
  assert.equal(workerStarted, false)
})

test('small, huge, and corrupted images are rejected before worker initialization', async () => {
  const image = new File(['image bytes'], 'message.png', { type: 'image/png' })
  let workerStarted = false
  const workerFactory = async () => {
    workerStarted = true
    throw new Error('Should not initialize')
  }
  const tooSmall = await analyzeScreenshot(image, () => {}, {
    imageInspector: async () => ({ width: 239, height: 600 }), workerFactory,
  })
  const tooLargeInPixels = await analyzeScreenshot(image, () => {}, {
    imageInspector: async () => ({ width: 6000, height: 5000 }), workerFactory,
  })
  const corrupted = await analyzeScreenshot(image, () => {}, {
    imageInspector: async () => { throw new Error('Invalid image data') }, workerFactory,
  })

  assert.equal(tooSmall.riskLevel, 'inconclusive')
  assert.equal(tooLargeInPixels.riskLevel, 'inconclusive')
  assert.equal(corrupted.riskLevel, 'inconclusive')
  assert.equal(workerStarted, false)
})

test('image dimension boundaries are accepted and rejected consistently', async () => {
  const image = new File(['image bytes'], 'message.png', { type: 'image/png' })
  let workerTerminated = false
  const workerFactory = async () => ({
    recognize: async () => ({ data: { text: 'This is ordinary readable screenshot content for our test.', confidence: 80 } }),
    terminate: async () => { workerTerminated = true },
  })
  const boundary = await analyzeScreenshot(image, () => {}, {
    imageInspector: async () => ({ width: 240, height: 120 }), workerFactory,
  })
  const onePixelBelow = await analyzeScreenshot(image, () => {}, {
    imageInspector: async () => ({ width: 240, height: 119 }), workerFactory,
  })

  assert.equal(boundary.riskLevel, 'no-obvious-warning-signs')
  assert.equal(onePixelBelow.riskLevel, 'inconclusive')
  assert.equal(workerTerminated, true)
})

test('cancelled screenshot analysis terminates its worker', async () => {
  const image = new File(['image bytes'], 'message.png', { type: 'image/png' })
  const controller = new AbortController()
  let terminated = false
  const pendingRecognition = new Promise(() => {})
  const resultPromise = analyzeScreenshot(image, () => {}, {
    signal: controller.signal,
    imageInspector: readableImageInspector,
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

test('cancellation during worker initialization terminates the worker when it becomes available', async () => {
  const image = new File(['image bytes'], 'message.png', { type: 'image/png' })
  const controller = new AbortController()
  let resolveWorker
  let terminated = false
  const resultPromise = analyzeScreenshot(image, () => {}, {
    signal: controller.signal,
    imageInspector: readableImageInspector,
    workerFactory: () => new Promise((resolve) => { resolveWorker = resolve }),
  })

  await new Promise((resolve) => setImmediate(resolve))
  controller.abort()
  const result = await resultPromise
  resolveWorker({ recognize: async () => ({ data: { text: '' } }), terminate: async () => { terminated = true } })
  await new Promise((resolve) => setImmediate(resolve))

  assert.equal(result.riskLevel, 'inconclusive')
  assert.match(result.summary, /stopped/i)
  assert.equal(terminated, true)
})
