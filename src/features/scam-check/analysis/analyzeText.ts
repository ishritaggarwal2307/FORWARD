import type { AnalysisResult, Finding, InputMode } from './types.ts'
import { analyzeUrl } from './analyzeUrl.ts'
import { analysisLimitation, classifyRisk, createInconclusiveResult } from './results.ts'

interface TextRule {
  id: string
  pattern: RegExp
  title: string
  explanation: string
  strength: Finding['strength']
  highConcernTrigger?: Finding['highConcernTrigger']
}

const authenticationRequest: TextRule = {
  id: 'credentials-request',
  pattern: /\b(?:send|share|reply with|provide|enter|confirm)\s+(?:your\s+)?(?:password|passcode|pin|one[- ]time code|verification code|security code|otp)\b|\b(?:password|passcode|one[- ]time code|verification code|security code|otp)\s+(?:is required|to unlock|to restore)\b/i,
  title: 'The message asks for a password or one-time code',
  explanation: 'A request to send a password, PIN, or one-time code can give someone access to an account.',
  strength: 'strong',
  highConcernTrigger: 'direct-authentication',
}

const accountThreat: TextRule = {
  id: 'account-access-threat',
  pattern: /\b(?:your\s+)?(?:bank\s+)?(?:account|access)\b.{0,55}\b(?:(?:will|may|could|can)\s+be\s+|(?:has been|is being|is about to be)\s+)?(?:blocked|suspended|locked|restricted|frozen|disabled|closed)\b|\b(?:block|suspend|lock|restrict|freeze|disable|close)\b.{0,35}\b(?:your\s+)?(?:bank\s+)?(?:account|access)\b/i,
  title: 'The message threatens to block or suspend account access',
  explanation: 'Account warnings can be legitimate, but a threat should be checked through a contact method you already trust.',
  strength: 'weak',
}

const kycExpiration: TextRule = {
  id: 'kyc-expiration-mentioned',
  pattern: /\b(?:kyc|identity verification|customer verification)\b.{0,60}\b(?:expire[sd]?|expiring|expiration|expiry|overdue|out of date)\b|\b(?:expire[sd]?|expiring|expiration|expiry|overdue|out of date)\b.{0,60}\b(?:kyc|identity verification|customer verification)\b/i,
  title: 'The message mentions expired or expiring KYC verification',
  explanation: 'A KYC deadline can be a normal account notice. The deadline alone is not a warning that the message is fraudulent.',
  strength: 'informational',
}

const bankingDetailsRequest: TextRule = {
  id: 'banking-details-request',
  pattern: /\b(?:update|verify|confirm|review|refresh|submit|provide|send|share|enter)\b.{0,55}\b(?:your\s+)?(?:bank(?:ing)?|financial|account|payment|card)\s+(?:details?|information|info|records?|profile)\b|\b(?:your\s+)?(?:bank(?:ing)?|financial|account|payment|card)\s+(?:details?|information|info|records?|profile)\b.{0,55}\b(?:update|verify|confirm|review|refresh|submit|provide|send|share|enter)\b/i,
  title: 'The message asks you to verify or update banking information',
  explanation: 'Unexpected requests to update financial details should be checked with the bank through a known channel.',
  strength: 'weak',
}

const personalInformationRequest: TextRule = {
  id: 'personal-information-request',
  pattern: /\b(?:send|share|provide|enter|confirm|submit)\s+(?:your\s+)?(?:social security number|national id|identity number|date of birth|personal details|identity details)\b/i,
  title: 'The message asks for sensitive personal details',
  explanation: 'Unexpected requests for identity information should be verified through a known official channel.',
  strength: 'weak',
}

const paymentRequest: TextRule = {
  id: 'payment-request',
  pattern: /\b(?:pay|transfer|send|wire)\s+(?:the\s+)?(?:money|funds|fee|payment|deposit|gift cards?|cryptocurrency|crypto|a wire transfer)\b/i,
  title: 'The message asks you to send money or use an unusual payment method',
  explanation: 'Payment requests can be legitimate, but transfers and gift-card or cryptocurrency payments may be difficult to reverse.',
  strength: 'weak',
}

const giftCardPurchaseRequest: TextRule = {
  id: 'gift-card-purchase-request',
  pattern: /\b(?:please\s+)?(?:you\s+(?:need|must|should)\s+to\s+|i\s+need\s+you\s+to\s+|we\s+need\s+you\s+to\s+|can\s+you\s+|could\s+you\s+)?(?:buy|purchase|order|get|pick up)\b.{0,35}\bgift cards?\b/i,
  title: 'The message asks you to buy gift cards',
  explanation: 'Gift cards can be legitimate gifts, but requests to buy them for someone else deserve an independent check.',
  strength: 'weak',
}

const verificationRequest = /\b(?:verify|confirm|update|review|refresh)\b.{0,45}\b(?:your\s+)?(?:account|kyc|identity|bank(?:ing)?|details?)\b|\b(?:your\s+)?(?:account|kyc|identity|bank(?:ing)?|details?)\b.{0,45}\b(?:verify|confirm|update|review|refresh)\b/i
const urgencyPattern = /\b(?:act now|immediately|urgent(?:ly)?|final warning|expires today|within \d+ hours?|limited time|right away|today or|by midnight)\b/i
const prizePattern = /\b(?:you(?:'|’)?ve|you have) won\b|\bclaim your (?:prize|reward|gift)\b|\b(?:lottery|prize draw|sweepstakes?|raffle) winnings\b/i
const prizeSelectionPattern = /\b(?:you have been|you(?:'|’)?ve been)\s+(?:selected|chosen)\s+(?:for|in)\s+(?:a\s+)?(?:prize draw|drawing|lottery|sweepstakes?|raffle)\b/i
const prizeContextPattern = /\b(?:prize|lottery|sweepstakes?|raffle|winnings|reward)\b/i
const prizeClaimActionPattern = /\b(?:register|claim|redeem|collect|receive|confirm|complete)\b/i
const prizeFeePattern = /\b(?:pay|send|transfer|cover|submit)\b.{0,35}\b(?:processing|administrative|admin|delivery|release|claim|tax)\s+fees?\b|\b(?:processing|administrative|admin|delivery|release|claim|tax)\s+fees?\b.{0,35}\b(?:prize|lottery|winnings|reward|draw)\b/i
const authorityPattern = /\b(?:your\s+)?(?:manager|boss|supervisor|director|executive|ceo|chief executive|owner|president)\b/i
const giftCardMentionPattern = /\bgift cards?\b/i
const giftCardValueRequestPattern = /\b(?:send|share|text|email|provide|give|forward|upload)\b.{0,65}\b(?:gift cards?|(?:redemption\s+)?codes?)\b|\bgift cards?\b.{0,45}\b(?:codes?|redemption codes?)\b/i
const giftCardPhotoRequestPattern = /\b(?:send|share|text|email|provide|give|forward|upload|take)\b.{0,65}\b(?:photos?|pictures?|images?)\b.{0,45}\bgift cards?\b|\bgift cards?\b.{0,65}\b(?:photos?|pictures?|images?)\b/i
const giftCardRequestPattern = /\b(?:buy|purchase|order|get|pick up|send|share|text|email|provide|give|forward|upload)\b.{0,65}\bgift cards?\b|\bgift cards?\b.{0,65}\b(?:codes?|redemption codes?|photos?|pictures?|images?)\b/i
const urlPattern = /(?:https?:\/\/|www\.)[^\s<>"']+/i

const detectionRules = [
  authenticationRequest,
  accountThreat,
  kycExpiration,
  bankingDetailsRequest,
  personalInformationRequest,
  paymentRequest,
  giftCardPurchaseRequest,
] satisfies readonly TextRule[]

function splitSentences(text: string): string[] {
  return text
    .split(/(?:[.!?;]+\s+|\r?\n+|\s+\b(?:but|however|instead|yet)\b\s+)/iu)
    .map((sentence) => sentence.trim().replace(/^[“"'‘]|[”"'’]$/gu, '').trim())
    .filter(Boolean)
}

function isSafetyOrEducationalContext(sentence: string): boolean {
  const trimmed = sentence.trim()
  const isReportedQuote = /\b(?:said|says|reads|read)\s*:\s*[“"'‘]/iu.test(trimmed)
  const isQuotedDiscussion = /[“"'‘][^”"'’]+[”"'’]/u.test(trimmed)
    && /\b(?:looks? suspicious|is suspicious|is an example|is a scam|is phishing|was a scam|is being discussed)\b/i.test(trimmed)
  return isReportedQuote
    || isQuotedDiscussion
    || /\b(?:be careful|beware|watch out)\s+of\s+(?:these\s+)?(?:scam\s+)?(?:messages|texts|emails)\b/i.test(sentence)
    || /\b(?:example\s+(?:of\s+(?:a\s+)?)?(?:scam|phishing|fraud)|(?:scam|phishing|fraud)\s+awareness|educational\s+(?:example|warning)|warning\s+about\s+(?:scams?|phishing|fraud))\b/i.test(sentence)
    || /\b(?:scammers?|fraudsters?)\s+(?:may|might|often|will)\s+ask\b/i.test(sentence)
}

function hasNearbyNegation(sentence: string, matchIndex: number): boolean {
  const precedingText = sentence.slice(Math.max(0, matchIndex - 32), matchIndex)
  return /\b(?:never|don't|do not|shouldn't|should not|must not|avoid|not to|won't|will not|is not|isn't|not be)\s+(?:(?:you|we|they)\s+)?(?:please\s+)?$/i.test(precedingText)
}

function isIndependentOfflineInstruction(sentence: string): boolean {
  const namesOfflineChannel = /\b(?:at|visit|go to|speak with|ask at)\b.{0,35}\b(?:nearest|local|your)?\s*(?:bank\s+)?branch\b|\b(?:in person|inside the bank|at a bank office)\b/i.test(sentence)
  const addsOnlineOrPressure = urlPattern.test(sentence)
    || urgencyPattern.test(sentence)
    || accountThreat.pattern.test(sentence)
    || authenticationRequest.pattern.test(sentence)

  return namesOfflineChannel && !addsOnlineOrPressure
}

function evidenceFor(sentence: string, pattern: RegExp): string | undefined {
  if (pattern === bankingDetailsRequest.pattern && isIndependentOfflineInstruction(sentence)) return undefined
  const globalPattern = new RegExp(pattern.source, `${pattern.flags.replace('g', '')}g`)
  for (const match of sentence.matchAll(globalPattern)) {
    if (match.index !== undefined && !hasNearbyNegation(sentence, match.index)) return match[0]
  }
  return undefined
}

function hasRelatedSignals(sentences: readonly string[], patterns: readonly RegExp[]): boolean {
  if (sentences.some((sentence) => patterns.every((pattern) => evidenceFor(sentence, pattern)))) return true

  return sentences.some((sentence, index) => {
    const nextSentence = sentences[index + 1]
    if (!nextSentence) return false
    const linked = /\b(?:because|therefore|so|otherwise|unless|as a result|to avoid|to prevent|if\s+.{1,40}\s+then)\b/i.test(`${sentence} ${nextSentence}`)
    return linked && patterns.every((pattern) => evidenceFor(sentence, pattern) || evidenceFor(nextSentence, pattern))
  })
}

function addRuleFindings(findings: Finding[], sentences: readonly string[]) {
  for (const sentence of sentences) {
    if (isSafetyOrEducationalContext(sentence)) continue
    for (const rule of detectionRules) {
      if (findings.some((finding) => finding.id === rule.id)) continue
      const evidence = evidenceFor(sentence, rule.pattern)
      if (evidence) {
        findings.push({ ...rule, evidence })
      }
    }
  }
}

function addContextFindings(findings: Finding[], sentences: readonly string[], activeText: string) {
  const activeSentences = sentences.filter((sentence) => !isSafetyOrEducationalContext(sentence))
  const hasKycDeadline = findings.some((finding) => finding.id === kycExpiration.id)
  const hasLink = activeSentences.some((sentence) => urlPattern.test(sentence))
  const hasVerificationRequest = activeSentences.some((sentence) => evidenceFor(sentence, verificationRequest))

  const verificationLinkSentence = activeSentences.find((sentence) =>
    urlPattern.test(sentence) && evidenceFor(sentence, verificationRequest),
  ) ?? (hasLink && hasKycDeadline && hasVerificationRequest
    ? activeSentences.find((sentence) => urlPattern.test(sentence))
    : undefined)

  if (verificationLinkSentence && !findings.some((finding) => finding.id === 'verification-link-with-request')) {
    const link = evidenceFor(verificationLinkSentence, urlPattern)
    findings.push({
      id: 'verification-link-with-request',
      title: 'A link is paired with an account or verification request',
      explanation: 'A link beside a request to verify or update account details deserves a closer check. This does not establish who owns the destination.',
      strength: 'weak',
      evidence: link,
    })
  }

  const urgencySentence = activeSentences.find((sentence) => {
    const hasUrgency = evidenceFor(sentence, urgencyPattern)
    if (!hasUrgency) return false
    return evidenceFor(sentence, accountThreat.pattern)
      || evidenceFor(sentence, bankingDetailsRequest.pattern)
      || evidenceFor(sentence, personalInformationRequest.pattern)
      || evidenceFor(sentence, authenticationRequest.pattern)
      || evidenceFor(sentence, giftCardRequestPattern)
      || (urlPattern.test(sentence) && evidenceFor(sentence, verificationRequest))
  })

  if (urgencySentence && !findings.some((finding) => finding.id === 'contextual-urgency')) {
    findings.push({
      id: 'contextual-urgency',
      title: 'Time pressure is paired with an account or information request',
      explanation: 'Urgency is more concerning when a message also threatens account access or asks you to verify, update, or share details.',
      strength: 'weak',
      evidence: evidenceFor(urgencySentence, urgencyPattern),
    })
  }

  const strongCombination = hasRelatedSignals(activeSentences, [accountThreat.pattern, bankingDetailsRequest.pattern])
    || hasRelatedSignals(activeSentences, [accountThreat.pattern, personalInformationRequest.pattern, urgencyPattern])
    || hasRelatedSignals(activeSentences, [accountThreat.pattern, personalInformationRequest.pattern, urlPattern])
    || hasRelatedSignals(activeSentences, [kycExpiration.pattern, bankingDetailsRequest.pattern, urgencyPattern])
    || hasRelatedSignals(activeSentences, [kycExpiration.pattern, bankingDetailsRequest.pattern, urlPattern])
    || hasRelatedSignals(activeSentences, [kycExpiration.pattern, verificationRequest, urlPattern, urgencyPattern])
    || hasRelatedSignals(activeSentences, [accountThreat.pattern, verificationRequest, urlPattern, urgencyPattern])

  if (strongCombination && !findings.some((finding) => finding.id === 'account-verification-combination')) {
    const evidence = findings
      .filter((finding) => ['account-access-threat', 'kyc-expiration-mentioned', 'banking-details-request', 'personal-information-request', 'verification-link-with-request', 'contextual-urgency'].includes(finding.id))
      .map((finding) => finding.evidence)
      .filter((value): value is string => Boolean(value))
      .slice(0, 4)
      .join(' · ')

    findings.push({
      id: 'account-verification-combination',
      title: 'Several account or verification warning signs appear together',
      explanation: 'An account or KYC threat is combined with a request to change sensitive details and added pressure or a link. Check through a contact method you already trust.',
      strength: 'strong',
      highConcernTrigger: 'contextual-combination',
      evidence: evidence || activeText.slice(0, 160),
    })
  }

  const prizeSelectionIndex = activeSentences.findIndex((_, index) => {
    const nearbyText = activeSentences.slice(index, index + 2).join(' ')
    return evidenceFor(nearbyText, prizeSelectionPattern) && evidenceFor(nearbyText, prizeClaimActionPattern)
  })
  const prizeSelectionEvidenceText = prizeSelectionIndex >= 0
    ? activeSentences.slice(prizeSelectionIndex, prizeSelectionIndex + 2).join(' ')
    : undefined
  if (prizeSelectionEvidenceText && !findings.some((finding) => finding.id === 'unexpected-prize-selection')) {
    findings.push({
      id: 'unexpected-prize-selection',
      title: 'The message says you were selected for a prize and asks you to register or claim it',
      explanation: 'A personalized prize selection followed by a request to register or claim should be checked through the promotion’s official channel.',
      strength: 'weak',
      evidence: `${evidenceFor(prizeSelectionEvidenceText, prizeSelectionPattern)} · ${evidenceFor(prizeSelectionEvidenceText, prizeClaimActionPattern)}`,
    })
  }

  const giftCardValueRequest = activeSentences.some((sentence) =>
    evidenceFor(sentence, giftCardMentionPattern) && evidenceFor(sentence, giftCardValueRequestPattern),
  )
  const giftCardPhotoRequest = activeSentences.some((sentence) => evidenceFor(sentence, giftCardPhotoRequestPattern))

  if ((giftCardValueRequest || giftCardPhotoRequest) && !findings.some((finding) => finding.id === 'gift-card-value-request')) {
    const sentence = activeSentences.find((item) => evidenceFor(item, giftCardValueRequestPattern) || evidenceFor(item, giftCardPhotoRequestPattern))
    findings.push({
      id: 'gift-card-value-request',
      title: giftCardPhotoRequest ? 'The message asks for a photo of a gift card' : 'The message asks you to share gift card codes',
      explanation: 'A gift card code or photo can let someone redeem its value. Verify the request with the person through a separate, trusted channel.',
      strength: 'strong',
      evidence: sentence ? evidenceFor(sentence, giftCardValueRequestPattern) ?? evidenceFor(sentence, giftCardPhotoRequestPattern) : undefined,
    })
  }

  const giftCardValueSentences = activeSentences.filter((sentence) =>
    evidenceFor(sentence, giftCardMentionPattern) && evidenceFor(sentence, giftCardValueRequestPattern),
  )
  const authorityGiftCardCombination = giftCardValueSentences.some((sentence) => evidenceFor(sentence, authorityPattern))
  const urgentGiftCardValueCombination = giftCardValueSentences.some((sentence) => evidenceFor(sentence, urgencyPattern))
  const secretGiftCardValueCombination = giftCardValueSentences.some((sentence) =>
    /\b(?:keep|keeping|kept)\b.{0,35}\b(?:secret|confidential|quiet|between us)\b|\bdon't tell\b/i.test(sentence),
  )
  if ((authorityGiftCardCombination || urgentGiftCardValueCombination || secretGiftCardValueCombination) && !findings.some((finding) => finding.id === 'gift-card-request-combination')) {
    findings.push({
      id: 'gift-card-request-combination',
      title: 'A gift card value transfer is paired with added pressure',
      explanation: 'A request to transfer gift card value combined with authority, urgency, or secrecy deserves an independent check. Confirm directly with the person using a known contact method.',
      strength: 'strong',
      highConcernTrigger: 'contextual-combination',
      evidence: activeSentences.filter((sentence) => evidenceFor(sentence, giftCardRequestPattern) || evidenceFor(sentence, urgencyPattern) || evidenceFor(sentence, authorityPattern)).slice(0, 2).join(' · '),
    })
  }

  const prizeFeeCombination = hasRelatedSignals(activeSentences, [prizeContextPattern, prizeFeePattern])
  const prizeBankingCombination = hasRelatedSignals(activeSentences, [prizeContextPattern, bankingDetailsRequest.pattern])
  if ((prizeFeeCombination || prizeBankingCombination) && !findings.some((finding) => finding.id === 'prize-claim-payment-combination')) {
    findings.push({
      id: 'prize-claim-payment-combination',
      title: prizeFeeCombination
        ? 'A prize claim is paired with a processing or release fee'
        : 'A prize claim is paired with a banking information request',
      explanation: 'Requests for a fee or banking details to release a prize deserve independent verification. This pattern alone does not verify who sent the message.',
      strength: 'strong',
      highConcernTrigger: 'contextual-combination',
      evidence: activeText.slice(0, 180),
    })
  }

  const prizeSentence = activeSentences.find((sentence) => evidenceFor(sentence, prizePattern))
  if (prizeSentence && !findings.some((finding) => finding.id === 'unexpected-prize')) {
    findings.push({
      id: 'unexpected-prize',
      title: 'The message promises an unexpected prize or reward',
      explanation: 'Unexpected rewards can be used to encourage people to click links or share personal details.',
      strength: 'weak',
      evidence: evidenceFor(prizeSentence, prizePattern),
    })
  }

}

function buildResult(inputMode: InputMode, findings: Finding[]): AnalysisResult {
  const riskLevel = classifyRisk(findings)
  const messages = {
    'high-concern': {
      title: 'High concern',
      summary: 'The review found a direct request for an authentication secret or a strong combination of warning signs.',
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
    inconclusive: {
      title: 'Inconclusive',
      summary: 'There was not enough usable information to complete this review.',
      recommendations: ['Try again with more readable content.', 'Verify unexpected requests through a trusted channel.'],
    },
    'no-obvious-warning-signs': {
      title: 'No obvious warning signs detected',
      summary: 'These checks did not find actionable warning patterns. Informational observations below are not proof of risk. This does not confirm the content is legitimate or safe.',
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

export function analyzeMessage(text: string): AnalysisResult {
  const normalized = text.trim()
  if (normalized.length < 5) {
    return createInconclusiveResult('message', 'There is not enough message text to review. Add the suspicious wording and try again.')
  }

  const sentences = splitSentences(normalized)
  const activeText = sentences.filter((sentence) => !isSafetyOrEducationalContext(sentence)).join(' ')
  const findings: Finding[] = []

  addRuleFindings(findings, sentences)
  addContextFindings(findings, sentences, activeText)

  const urls = activeText.match(/(?:https?:\/\/|www\.)[^\s<>"']+/gi) ?? []
  for (const [index, rawUrl] of urls.entries()) {
    const cleanedUrl = rawUrl.replace(/[),.!?;:]+$/, '')
    const urlResult = analyzeUrl(cleanedUrl)
    for (const finding of urlResult.findings) {
      findings.push({ ...finding, id: `message-link-${index + 1}-${finding.id}` })
    }
  }

  return buildResult('message', findings)
}
