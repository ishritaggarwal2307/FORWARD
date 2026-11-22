import { useEffect, useRef, useState, type FormEvent } from 'react'
import './ScamCheck.css'
import { analyzeMessage } from './analysis/analyzeText'
import { analyzeUrl } from './analysis/analyzeUrl'
import { analyzeScreenshot } from './analysis/analyzeScreenshot'
import type { AnalysisResult, InputMode, OcrProgress } from './analysis/types'
import { InputMethodPicker } from './components/InputMethodPicker'
import { ScreenshotUpload } from './components/ScreenshotUpload'

type AnalysisStatus = 'idle' | 'analyzing' | 'complete'

function riskLabel(riskLevel: AnalysisResult['riskLevel']) {
  return riskLevel.replaceAll('-', ' ')
}

function AnalysisResults({ result, onReset }: { result: AnalysisResult; onReset: () => void }) {
  return (
    <section className="analysis-results" aria-labelledby="analysis-results-title">
      <p className="visually-hidden" role="status" aria-live="polite">Review complete. {result.title}. {result.summary}</p>
      <div className={`risk-summary risk-${result.riskLevel}`}>
        <div className="risk-summary-heading">
          <span className="risk-symbol" aria-hidden="true">{result.riskLevel === 'high-concern' ? '!' : result.riskLevel === 'inconclusive' ? '?' : '•'}</span>
          <div>
            <p className="result-eyebrow">REVIEW RESULT · {riskLabel(result.riskLevel)}</p>
            <h2 id="analysis-results-title">{result.title}</h2>
          </div>
        </div>
        <p className="risk-summary-copy">{result.summary}</p>
        <p className="local-analysis-label">Rule-based review · No accuracy score</p>
      </div>

      <section className="result-section" aria-labelledby="findings-title">
        <div className="result-section-heading"><p className="result-eyebrow">WHAT WE NOTICED</p><h3 id="findings-title">Warning signs</h3></div>
        {result.findings.length > 0 ? (
          <ul className="finding-list">
            {result.findings.map((finding) => (
              <li className="finding" key={finding.id}>
                <span className={`finding-marker severity-${finding.severity}`} aria-hidden="true">{finding.severity === 'high' ? '!' : 'i'}</span>
                <div>
                  <div className="finding-title-row"><h4>{finding.title}</h4><span>{finding.severity === 'high' ? 'HIGH CONCERN' : finding.severity === 'moderate' ? 'CHECK THIS' : 'NOTICE'}</span></div>
                  <p>{finding.explanation}</p>
                  {finding.evidence && <blockquote>“{finding.evidence}”</blockquote>}
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <p className="no-findings">This review did not find any of its listed warning patterns. That is not a safety guarantee.</p>
        )}
      </section>

      <section className="result-section recommendations" aria-labelledby="recommendations-title">
        <div className="result-section-heading"><p className="result-eyebrow">NEXT STEPS</p><h3 id="recommendations-title">What you can do</h3></div>
        <ul>{result.recommendations.map((recommendation) => <li key={recommendation}>{recommendation}</li>)}</ul>
      </section>

      <aside className="limitations-note" aria-labelledby="limitations-title">
        <span className="limitations-mark" aria-hidden="true">i</span>
        <div><h3 id="limitations-title">Know the limits</h3>{result.limitations.map((limitation) => <p key={limitation}>{limitation}</p>)}</div>
      </aside>
      <button className="reset-analysis" onClick={onReset} type="button">Start a new check <span aria-hidden="true">↺</span></button>
    </section>
  )
}

export default function ScamCheckPage() {
  const ocrController = useRef<AbortController | null>(null)
  const resultsRef = useRef<HTMLElement>(null)
  const [inputMode, setInputMode] = useState<InputMode>('message')
  const [message, setMessage] = useState('')
  const [url, setUrl] = useState('')
  const [image, setImage] = useState<File | null>(null)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [status, setStatus] = useState<AnalysisStatus>('idle')
  const [progress, setProgress] = useState<OcrProgress | null>(null)
  const [formError, setFormError] = useState('')

  useEffect(() => {
    document.title = 'Scam Check | FORWARD?'
    return () => {
      ocrController.current?.abort()
      ocrController.current = null
      document.title = 'FORWARD? — Think Before You Click'
    }
  }, [])

  useEffect(() => {
    if (result) {
      resultsRef.current?.focus({ preventScroll: true })
      resultsRef.current?.scrollIntoView({ block: 'start' })
    }
  }, [result])

  function resetAnalysis() {
    ocrController.current?.abort()
    ocrController.current = null
    setMessage('')
    setUrl('')
    setImage(null)
    setResult(null)
    setProgress(null)
    setFormError('')
    setStatus('idle')
  }

  function selectMode(mode: InputMode) {
    setInputMode(mode)
    setResult(null)
    setFormError('')
    setStatus('idle')
    setProgress(null)
    if (mode !== 'screenshot') setImage(null)
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setFormError('')
    setResult(null)

    if (inputMode === 'message') {
      if (!message.trim()) {
        setFormError('Paste the suspicious message before starting the review.')
        return
      }
      setResult(analyzeMessage(message))
      setStatus('complete')
      return
    }

    if (inputMode === 'url') {
      if (!url.trim()) {
        setFormError('Enter a web address before starting the review.')
        return
      }
      setResult(analyzeUrl(url))
      setStatus('complete')
      return
    }

    if (!image) {
      setFormError('Choose a screenshot before starting the review.')
      return
    }

    setStatus('analyzing')
    setProgress({ stage: 'loading', progress: 0 })
    const selectedImage = image
    const controller = new AbortController()
    ocrController.current = controller
    try {
      const screenshotResult = await analyzeScreenshot(selectedImage, setProgress, { signal: controller.signal })
      if (!controller.signal.aborted) setResult(screenshotResult)
    } finally {
      if (ocrController.current === controller) {
        ocrController.current = null
        setImage(null)
        setProgress(null)
        setStatus(controller.signal.aborted ? 'idle' : 'complete')
      }
    }
  }

  return (
    <div className="scam-check-page">
      <section className="scam-check-intro section-wrap" aria-labelledby="scam-check-title">
        <p className="eyebrow"><span className="eyebrow-line" /> A SECOND LOOK, WITH REASONS</p>
        <h1 id="scam-check-title">Pause. Check.<br /><span>Then decide.</span></h1>
        <p>Review a suspicious message, link, or screenshot. We’ll show the warning signs we find and explain what they may mean.</p>
      </section>

      <div className="scam-check-layout section-wrap">
        <section className="check-panel" aria-labelledby="input-title">
          <div className="check-panel-heading"><p className="result-eyebrow">PRIVATE, LOCAL REVIEW</p><h2 id="input-title">What would you like to check?</h2><p>Choose one item. Your message and link stay in this browser.</p></div>
          <InputMethodPicker disabled={status === 'analyzing'} value={inputMode} onChange={selectMode} />

          <form className="check-form" noValidate onSubmit={handleSubmit}>
            {inputMode === 'message' && (
              <div className="form-field">
                <label htmlFor="message-input">Suspicious message</label>
                <textarea
                  autoComplete="off"
                  id="message-input"
                  maxLength={5000}
                  onChange={(event) => { setMessage(event.target.value); setResult(null); setStatus('idle') }}
                  placeholder="Paste the SMS, chat, or email text here…"
                  value={message}
                />
                <div className="field-helper-row"><span>Remove names, account details, or codes before pasting.</span><span>{message.length} / 5000</span></div>
              </div>
            )}
            {inputMode === 'url' && (
              <div className="form-field">
                <label htmlFor="url-input">Suspicious website address</label>
                <input
                  autoComplete="off"
                  id="url-input"
                  maxLength={2048}
                  onChange={(event) => { setUrl(event.target.value); setResult(null); setStatus('idle') }}
                  placeholder="example.com/path"
                  spellCheck={false}
                  type="url"
                  value={url}
                />
                <p className="field-help">We inspect the address only. We never open or visit the link.</p>
              </div>
            )}
            {inputMode === 'screenshot' && (
              <ScreenshotUpload disabled={status === 'analyzing'} file={image} onSelect={(file) => { setImage(file); setResult(null); setStatus('idle'); setFormError('') }} />
            )}

            {formError && <p className="field-error" id="form-error" role="alert">{formError}</p>}
            {status === 'analyzing' && (
              <div className="ocr-progress" role="status" aria-live="polite">
                <span className="progress-indicator" aria-hidden="true" />
                <div><strong>{progress?.stage === 'recognizing' ? 'Reading text in your browser' : 'Preparing local OCR'}</strong><small>{Math.round((progress?.progress ?? 0) * 100)}% · Your screenshot is not uploaded</small></div>
              </div>
            )}
            <div className="form-actions">
              <button className="button button-lime analyze-button" disabled={status === 'analyzing'} type="submit">
                {status === 'analyzing' ? 'Reviewing locally…' : 'Review for warning signs'} <span className="arrow" aria-hidden="true">↗</span>
              </button>
              {status === 'analyzing'
                ? <button className="clear-form-button" onClick={resetAnalysis} type="button">Stop and clear</button>
                : (message || url || image || result) && <button className="clear-form-button" onClick={resetAnalysis} type="button">Clear and start over</button>}
            </div>
          </form>
          <p className="rule-disclosure"><span aria-hidden="true">i</span> Checks use clear, rule-based indicators. A result is guidance, not proof that something is safe or a scam.</p>
        </section>

        <aside className="how-check-works" aria-labelledby="how-check-works-title">
          <p className="result-eyebrow">HOW THE REVIEW WORKS</p>
          <h2 id="how-check-works-title">See the reason.<br /><span>Make your call.</span></h2>
          <ol>
            <li><span>01</span><div><strong>We look for signals</strong><p>Rules check wording or link structure for known warning patterns.</p></div></li>
            <li><span>02</span><div><strong>We show our work</strong><p>Each finding explains what triggered it and why it may matter.</p></div></li>
            <li><span>03</span><div><strong>You choose what’s next</strong><p>Use practical steps to verify the request before acting.</p></div></li>
          </ol>
          <div className="always-verify"><span aria-hidden="true">↗</span><p>No obvious warning signs is not the same as verified safe. Check unexpected requests through a channel you trust.</p></div>
        </aside>
      </div>

      {result && <section aria-label="Scam Check results" className="section-wrap results-wrap" ref={resultsRef} tabIndex={-1}><AnalysisResults result={result} onReset={resetAnalysis} /></section>}
    </div>
  )
}
