import { analyzeMessage } from './analyzeText.ts'
import { createInconclusiveResult } from './results.ts'
import type { AnalysisResult, OcrProgress } from './types.ts'

const minimumUsefulCharacters = 18
const maximumImageBytes = 10 * 1024 * 1024

interface OcrWorker {
  recognize(image: File): Promise<{ data: { text: string } }>
  terminate(): Promise<unknown>
}

interface OcrLogMessage {
  status: string
  progress: number
}

type OcrWorkerFactory = (logger: (message: OcrLogMessage) => void) => Promise<OcrWorker>

interface ScreenshotAnalysisOptions {
  workerFactory?: OcrWorkerFactory
  signal?: AbortSignal
}

const createLocalOcrWorker: OcrWorkerFactory = async (logger) => {
  const { createWorker } = await import('tesseract.js')
  return createWorker('eng', 1, { logger })
}

export function analyzeExtractedScreenshotText(text: string): AnalysisResult {
  const extractedText = text.trim()
  const meaningfulCharacters = extractedText.replace(/\s/g, '').length
  const wordCount = extractedText.match(/[\p{L}\p{N}]{2,}/gu)?.length ?? 0

  if (meaningfulCharacters < minimumUsefulCharacters || wordCount < 3) {
    return createInconclusiveResult(
      'screenshot',
      'We could not read enough text to review this image. Try a sharper, well-lit screenshot that includes the full message.',
    )
  }

  const textResult = analyzeMessage(extractedText)
  return {
    ...textResult,
    inputMode: 'screenshot',
    limitations: [
      ...textResult.limitations,
      'Text was extracted with English OCR, which can miss or misread small, stylized, low-contrast, or handwritten text.',
    ],
  }
}

export async function analyzeScreenshot(
  image: File,
  onProgress: (progress: OcrProgress) => void,
  { workerFactory = createLocalOcrWorker, signal }: ScreenshotAnalysisOptions = {},
): Promise<AnalysisResult> {
  if (signal?.aborted) {
    return createInconclusiveResult('screenshot', 'This review was stopped. Choose the screenshot again when you are ready.')
  }
  if (!image.type.startsWith('image/') || image.size === 0 || image.size > maximumImageBytes) {
    return createInconclusiveResult('screenshot', 'Choose a supported image under 10 MB to review.')
  }

  let worker: OcrWorker | undefined
  let workerTerminated = false
  let cancelRecognition: (() => void) | undefined
  const terminateWorker = async () => {
    if (worker && !workerTerminated) {
      workerTerminated = true
      await worker.terminate()
    }
  }
  const stopWorker = () => {
    void terminateWorker().catch(() => undefined)
    cancelRecognition?.()
  }

  try {
    worker = await workerFactory((message) => {
      const { status, progress } = message
      const stage = /recogniz|segment/i.test(status) ? 'recognizing' : 'loading'
      onProgress({ stage, progress: Math.max(0, Math.min(1, progress)) })
    })

    signal?.addEventListener('abort', stopWorker, { once: true })
    if (signal?.aborted) {
      await terminateWorker()
      return createInconclusiveResult('screenshot', 'This review was stopped. Choose the screenshot again when you are ready.')
    }

    const recognition = worker.recognize(image)
    const response = signal
      ? await Promise.race([
          recognition,
          new Promise<null>((resolve) => { cancelRecognition = () => resolve(null) }),
        ])
      : await recognition
    cancelRecognition = undefined
    if (!response) {
      return createInconclusiveResult('screenshot', 'This review was stopped. Choose the screenshot again when you are ready.')
    }

    const { data } = response
    if (signal?.aborted) {
      return createInconclusiveResult('screenshot', 'This review was stopped. Choose the screenshot again when you are ready.')
    }
    return analyzeExtractedScreenshotText(data.text)
  } catch {
    if (signal?.aborted) {
      return createInconclusiveResult('screenshot', 'This review was stopped. Choose the screenshot again when you are ready.')
    }
    return createInconclusiveResult(
      'screenshot',
      'The image could not be read. Check your connection for the first-time OCR setup, then try a clearer image.',
    )
  } finally {
    signal?.removeEventListener('abort', stopWorker)
    await terminateWorker().catch(() => undefined)
  }
}
