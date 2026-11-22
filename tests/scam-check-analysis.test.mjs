import assert from 'node:assert/strict'
import test from 'node:test'
import { analyzeMessage } from '../src/features/scam-check/analysis/analyzeText.ts'
import { analyzeUrl } from '../src/features/scam-check/analysis/analyzeUrl.ts'
import {
  analyzeExtractedScreenshotText,
  analyzeScreenshot,
} from '../src/features/scam-check/analysis/analyzeScreenshot.ts'

test('message review explains high concern indicators with quoted evidence', () => {
  const result = analyzeMessage('Your account is locked. Send your verification code immediately.')

  assert.equal(result.inputMode, 'message')
  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
  assert.ok(result.findings.every((finding) => finding.evidence))
  assert.match(result.summary, /deserves extra care/i)
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

  assert.equal(result.riskLevel, 'high-concern')
  assert.equal(result.findings[0].id, 'embedded-credentials')
  assert.match(result.limitations[0], /does not visit the site/i)
})

test('URL review avoids a safe verdict and reports unencrypted HTTP as a warning', () => {
  const clean = analyzeUrl('https://example.com')
  const http = analyzeUrl('http://example.com')

  assert.equal(clean.riskLevel, 'no-obvious-warning-signs')
  assert.match(clean.summary, /does not verify.*safe/i)
  assert.equal(http.riskLevel, 'some-warning-signs')
  assert.equal(http.findings[0].id, 'unencrypted-connection')
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
