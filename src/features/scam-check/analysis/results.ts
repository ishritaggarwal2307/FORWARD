import type { AnalysisResult, Finding, InputMode, RiskLevel } from './types.ts'

export const analysisLimitation =
  'This is a local, English-language rule-based review. It can miss paraphrases and context, and can flag legitimate messages. It does not check live threat databases, verify who sent the content, or prove that a message or link is safe.'

export function classifyRisk(findings: readonly Finding[]): RiskLevel {
  if (findings.some((finding) => finding.highConcernTrigger)) return 'high-concern'
  if (findings.some((finding) => finding.strength === 'strong' || finding.strength === 'weak')) {
    return 'some-warning-signs'
  }
  return 'no-obvious-warning-signs'
}

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
