import type { AnalysisResult, InputMode } from './types.ts'

export const analysisLimitation =
  'This is a local, rule-based review. It does not check live threat databases, verify who sent the content, or prove that a message or link is safe.'

export function createInconclusiveResult(inputMode: InputMode, reason: string): AnalysisResult {
  return {
    inputMode,
    riskLevel: 'inconclusive',
    title: 'Inconclusive',
    summary: reason,
    findings: [],
    recommendations: [
      'Try again with more readable text or a clearer screenshot.',
      'Until you can verify the sender, avoid clicking links or sharing sensitive information.',
    ],
    limitations: [analysisLimitation],
  }
}
