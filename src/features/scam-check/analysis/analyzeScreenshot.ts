import { analyzeMessage } from './analyzeText.ts'
import { createInconclusiveResult } from './results.ts'
import type { AnalysisResult, OcrProgress } from './types.ts'

const minimumUsefulCharacters = 18
const minimumOcrConfidence = 35
const maximumImageBytes = 10 * 1024 * 1024
const minimumImageWidth = 240
const minimumImageHeight = 120
const maximumImagePixels = 24_000_000
const supportedImageTypes = new Set(['image/jpeg', 'image/png', 'image/webp'])

interface OcrRecognition {
  data: { text: string; confidence?: number }
}

interface OcrWorker {
  recognize(image: File): Promise<OcrRecognition>
  terminate(): Promise<unknown>
}

interface OcrLogMessage {
  status: string
  progress: number
}

interface ImageDimensions {
  width: number
  height: number
}

type OcrWorkerFactory = (logger: (message: OcrLogMessage) => void) => Promise<OcrWorker>
type ImageInspector = (image: File) => Promise<ImageDimensions>

interface ScreenshotAnalysisOptions {
  workerFactory?: OcrWorkerFactory
  imageInspector?: ImageInspector
  signal?: AbortSignal
}

const createLocalOcrWorker: OcrWorkerFactory = async (logger) => {
  const { createWorker } = await import('tesseract.js')
  return createWorker('eng', 1, { logger })
}

async function inspectImageDimensions(image: File): Promise<ImageDimensions> {
  if (typeof createImageBitmap !== 'function') {
    throw new Error('Image decoding is not available in this browser.')
  }

  const bitmap = await createImageBitmap(image)
  try {
    return { width: bitmap.width, height: bitmap.height }
  } finally {
    bitmap.close()
  }
}

function inconclusiveImage(reason: string) {
  return createInconclusiveResult('screenshot', reason)
}

export function analyzeExtractedScreenshotText(text: string, ocrConfidence?: number): AnalysisResult {
  const extractedText = text.trim()
  const meaningfulCharacters = extractedText.replace(/\s/g, '').length
  const wordCount = extractedText.match(/[\p{L}\p{N}]{2,}/gu)?.length ?? 0
  const nonWhitespaceCharacters = [...extractedText].filter((character) => !/\s/u.test(character))
  const readableCharacters = nonWhitespaceCharacters.filter((character) => /[\p{L}\p{N}]/u.test(character)).length
  const garbledRatio = nonWhitespaceCharacters.length > 0
    ? 1 - readableCharacters / nonWhitespaceCharacters.length
    : 1

  if (
    meaningfulCharacters < minimumUsefulCharacters
    || wordCount < 3
    || garbledRatio > 0.35
    || (ocrConfidence !== undefined && (!Number.isFinite(ocrConfidence) || ocrConfidence < minimumOcrConfidence))
  ) {
    return inconclusiveImage(
      'The screenshot text could not be read reliably enough to review. Try a clearer, sharper image with the full message visible.',
    )
  }

  const textResult = analyzeMessage(extractedText)
  return {
    ...textResult,
    inputMode: 'screenshot',
    limitations: [
      ...textResult.limitations,
      'Text was extracted with English OCR. Small, stylized, low-contrast, handwritten, or non-English text may be missed or misread. OCR readability is not a scam-risk score.',
    ],
  }
}

export async function analyzeScreenshot(
  image: File,
  onProgress: (progress: OcrProgress) => void,
  { workerFactory = createLocalOcrWorker, imageInspector = inspectImageDimensions, signal }: ScreenshotAnalysisOptions = {},
): Promise<AnalysisResult> {
  if (signal?.aborted) {
    return inconclusiveImage('This review was stopped. Choose the screenshot again when you are ready.')
  }
  if (!supportedImageTypes.has(image.type) || image.size === 0 || image.size > maximumImageBytes) {
    return inconclusiveImage('Choose a JPG, PNG, or WebP image under 10 MB to review.')
  }

  try {
    const dimensions = await imageInspector(image)
    if (signal?.aborted) {
      return inconclusiveImage('This review was stopped. Choose the screenshot again when you are ready.')
    }
    if (
      dimensions.width < minimumImageWidth
      || dimensions.height < minimumImageHeight
      || dimensions.width * dimensions.height > maximumImagePixels
    ) {
      return inconclusiveImage('This image is too small or too large in pixel dimensions to review reliably. Choose a clearer screenshot.')
    }
  } catch {
    if (signal?.aborted) {
      return inconclusiveImage('This review was stopped. Choose the screenshot again when you are ready.')
    }
    return inconclusiveImage('This image could not be decoded. It may be damaged or use an unsupported image encoding.')
  }

  let worker: OcrWorker | undefined
  let workerTerminated = false
  let cancelOperation: (() => void) | undefined
  const cancelled = new Promise<null>((resolve) => {
    cancelOperation = () => resolve(null)
  })

  const terminateWorker = async (target: OcrWorker | undefined = worker) => {
    if (target && !workerTerminated) {
      workerTerminated = true
      await target.terminate()
    }
  }

  const onAbort = () => {
    cancelOperation?.()
    void terminateWorker().catch(() => undefined)
  }

  signal?.addEventListener('abort', onAbort, { once: true })

  try {
    const workerPromise = workerFactory((message) => {
      const stage = /recogniz|segment/i.test(message.status) ? 'recognizing' : 'loading'
      onProgress({ stage, progress: Math.max(0, Math.min(1, message.progress)) })
    })

    // If initialization completes after cancellation, still terminate that late-created worker.
    void workerPromise.then((createdWorker) => {
      if (signal?.aborted) void terminateWorker(createdWorker).catch(() => undefined)
    }).catch(() => undefined)

    const initializedWorker = signal ? await Promise.race([workerPromise, cancelled]) : await workerPromise
    if (!initializedWorker || signal?.aborted) {
      if (initializedWorker) await terminateWorker(initializedWorker).catch(() => undefined)
      return inconclusiveImage('This review was stopped. Choose the screenshot again when you are ready.')
    }
    worker = initializedWorker

    const recognition = worker.recognize(image)
    const response = signal ? await Promise.race([recognition, cancelled]) : await recognition
    if (!response || signal?.aborted) {
      return inconclusiveImage('This review was stopped. Choose the screenshot again when you are ready.')
    }

    return analyzeExtractedScreenshotText(response.data.text, response.data.confidence)
  } catch {
    if (signal?.aborted) {
      return inconclusiveImage('This review was stopped. Choose the screenshot again when you are ready.')
    }
    return inconclusiveImage('The image could not be read. Check your connection for the first-time English OCR setup, then try a clearer image.')
  } finally {
    signal?.removeEventListener('abort', onAbort)
    cancelOperation = undefined
    await terminateWorker().catch(() => undefined)
  }
}
