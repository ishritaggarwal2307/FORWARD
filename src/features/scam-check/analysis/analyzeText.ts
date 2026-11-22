import type { AnalysisResult, Finding, InputMode } from './types.ts'
import { analyzeUrl } from './analyzeUrl.ts'
import { analysisLimitation, createInconclusiveResult } from './results.ts'

function buildResult(inputMode: InputMode, findings: Finding[]): AnalysisResult {
  const hasHighConcern = findings.some((finding) => finding.severity === 'high')
  const riskLevel = hasHighConcern
    ? 'high-concern'
    : findings.length > 0
      ? 'some-warning-signs'
      : 'no-obvious-warning-signs'

  const messages = {
    'high-concern': {
      title: 'High concern',
      summary: 'The review found a direct request or link pattern that deserves extra care.',
      recommendations: [
        'Do not click links, reply, or share passwords, codes, or payment details.',
        'Contact the organisation using a number or website you already know is genuine.',
        'Use the messaging or email service’s report and block options if the message is unwanted.',
      ],
    },
    'some-warning-signs': {
      title: 'Some warning signs',
      summary: 'The review found details worth checking before you respond.',
      recommendations: [
        'Pause before clicking or replying.',
        'Verify the request through a separate, trusted contact method.',
        'Do not share sensitive information until you have confirmed who contacted you.',
      ],
    },
    'no-obvious-warning-signs': {
      title: 'No obvious warning signs detected',
      summary: 'These checks did not find any of the patterns they look for. That does not confirm the content is legitimate or safe.',
      recommendations: [
        'Check the sender and destination carefully before taking action.',
        'Use a trusted channel to confirm unexpected requests, especially for money or account access.',
      ],
    },
  } as const

  return {
    inputMode,
    riskLevel,
    ...messages[riskLevel],
    findings,
    limitations: [analysisLimitation],
  }
}

interface TextRule {
  id: string
  pattern: RegExp
  title: string
  explanation: string
  severity: Finding['severity']
}

const textRules: TextRule[] = [
  {
    id: 'credentials-request',
    pattern: /\b(?:send|share|reply with|provide|enter|confirm)\s+(?:your\s+)?(?:password|passcode|pin|one[- ]time code|verification code|security code|otp)\b|\b(?:password|passcode|one[- ]time code|verification code|security code|otp)\s+(?:is required|to unlock|to restore)\b/i,
    title: 'The message asks for a secret code or password',
    explanation: 'A request to send a password, PIN, or one-time code can give someone access to an account.',
    severity: 'high',
  },
  {
    id: 'payment-request',
    pattern: /\b(?:pay|transfer|send|wire)\s+(?:the\s+)?(?:money|funds|fee|payment|deposit)\b|\b(?:gift cards?|crypto(?:currency)?|wire transfer)\b/i,
    title: 'The message mentions sending money or unusual payment',
    explanation: 'Requests to transfer money or pay with gift cards or cryptocurrency are difficult to reverse. Verify them independently.',
    severity: 'high',
  },
  {
    id: 'personal-information',
    pattern: /\b(?:send|share|provide|enter|confirm)\s+(?:your\s+)?(?:bank details|card details|social security number|national id|identity number|date of birth)\b/i,
    title: 'The message asks for sensitive personal details',
    explanation: 'Unexpected requests for identity or financial information should be verified through a known official channel.',
    severity: 'high',
  },
  {
    id: 'urgent-pressure',
    pattern: /\b(?:act now|immediately|urgent|final warning|expires today|within \d+ hours?|account (?:is )?(?:locked|suspended|restricted)|limited time)\b/i,
    title: 'The message uses urgency or threatens a consequence',
    explanation: 'Pressure to act quickly can make it harder to check whether a request is genuine.',
    severity: 'moderate',
  },
  {
    id: 'unexpected-prize',
    pattern: /\b(?:you(?:'|’)ve|you have) won\b|\bclaim your (?:prize|reward|gift)\b/i,
    title: 'The message promises an unexpected prize or reward',
    explanation: 'Unexpected rewards can be used to persuade people to click links or share personal details.',
    severity: 'moderate',
  },
]

function evidenceFor(text: string, pattern: RegExp): string | undefined {
  const match = pattern.exec(text)
  return match?.[0]
}

export function analyzeMessage(text: string): AnalysisResult {
  const normalized = text.trim()
  if (normalized.length < 5) {
    return createInconclusiveResult('message', 'There is not enough message text to review. Add the suspicious wording and try again.')
  }

  const findings: Finding[] = textRules.flatMap((rule) => {
    const evidence = evidenceFor(normalized, rule.pattern)
    return evidence ? [{ ...rule, evidence }] : []
  })

  const urls = normalized.match(/(?:https?:\/\/|www\.)[^\s<>"']+/gi) ?? []
  for (const [index, rawUrl] of urls.entries()) {
    const cleanedUrl = rawUrl.replace(/[),.!?;:]+$/, '')
    const urlResult = analyzeUrl(cleanedUrl)
    for (const finding of urlResult.findings) {
      findings.push({ ...finding, id: `message-link-${index + 1}-${finding.id}` })
    }
  }

  return buildResult('message', findings)
}
