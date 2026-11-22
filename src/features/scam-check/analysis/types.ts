export type InputMode = 'message' | 'url' | 'screenshot'

export type RiskLevel =
  | 'high-concern'
  | 'some-warning-signs'
  | 'inconclusive'
  | 'no-obvious-warning-signs'

export type FindingSeverity = 'high' | 'moderate' | 'informational'

export interface Finding {
  id: string
  title: string
  explanation: string
  severity: FindingSeverity
  evidence?: string
}

export interface AnalysisResult {
  inputMode: InputMode
  riskLevel: RiskLevel
  title: string
  summary: string
  findings: readonly Finding[]
  recommendations: readonly string[]
  limitations: readonly string[]
}

export interface OcrProgress {
  stage: 'loading' | 'recognizing'
  progress: number
}
