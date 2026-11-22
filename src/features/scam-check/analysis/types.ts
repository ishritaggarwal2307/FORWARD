export type InputMode = 'message' | 'url' | 'screenshot'

export type RiskLevel =
  | 'high-concern'
  | 'some-warning-signs'
  | 'inconclusive'
  | 'no-obvious-warning-signs'

export type FindingStrength = 'informational' | 'weak' | 'strong'
export type HighConcernTrigger = 'direct-authentication' | 'contextual-combination'

export interface Finding {
  id: string
  title: string
  explanation: string
  strength: FindingStrength
  highConcernTrigger?: HighConcernTrigger
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
