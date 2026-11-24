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
  pattern: /\b(?:send|share|disclose|reply with|provide|enter|confirm|submit)\s+(?:(?:your|the|an?)\s+)?(?:(?:(?:net|online)[ -])?banking\s+)?(?:password|passcode|pin|one[- ]time code|verification code|security code|otp|credentials?|login credentials?)\b|\b(?:refund|account|transaction|payment|debit)\b[\s\S]{0,45}\b(?:requires?|needs?)\s*[:,-]?\s+(?:(?:your|an?)\s*[:,-]?\s*)?(?:otp|one[- ]time code|verification code|security code|password|passcode|pin)\b|\b(?:cancel|reverse|release|restore|unlock)\b[\s\S]{0,35}\b(?:this\s+)?(?:transaction|payment|debit|refund|account)\b[\s\S]{0,25}\bwith\s+(?:your\s+)?(?:otp|one[- ]time code|verification code|security code|password|passcode|pin)\b|\b(?:provide|send|share|disclose|enter|submit|confirm)\s+(?:your\s+)?(?:(?:(?:net|online)[ -])?banking\s+)?(?:credentials?|login credentials?)\s+(?:to|with|for)\b/i,
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

const accountSecurityAlert: TextRule = {
  id: 'account-security-alert',
  pattern: /\baccount takeover\b|\bunauthori[sz]ed account activity\b|\b(?:account|profile|online banking)\b.{0,55}\b(?:compromis(?:ed|e)|unauthori[sz]ed (?:access|login|sign[ -]?in|activity)|taken over|takeover|suspicious|unusual|unfamiliar)\b|\b(?:compromis(?:ed|e)|unauthori[sz]ed (?:access|login|sign[ -]?in|activity)|taken over|suspicious|unusual|unfamiliar)\b.{0,55}\b(?:account|profile|login|sign[ -]?in|access|activity)\b|\b(?:suspicious|unusual|unfamiliar|new)\s+(?:login|sign[ -]?in|access attempt|account activity)\b|\b(?:login|sign[ -]?in)\b.{0,35}\b(?:from\s+a\s+)?new (?:device|location)\b|\bnew device\b.{0,30}\b(?:login|sign[ -]?in|access)\b/i,
  title: 'The message reports unusual account access or activity',
  explanation: 'Security alerts can be legitimate. This observation does not verify the alert or the sender; check account activity through the official app or a contact method you already trust.',
  strength: 'informational',
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

const bankingIdentifierRequest: TextRule = {
  id: 'banking-identifier-request',
  pattern: /\b(?:send|share|provide|enter|submit|confirm|verify|update)\b.{0,45}\b(?:your\s+)?(?:bank\s+)?(?:account number|ifsc(?: code)?|routing number|banking customer id|net banking user(?:name| id))\b|\b(?:your\s+)?(?:bank\s+)?(?:account number|ifsc(?: code)?|routing number|banking customer id|net banking user(?:name| id))\b.{0,45}\b(?:send|share|provide|enter|submit|confirm|verify|update)\b/i,
  title: 'The message asks you to provide a banking identifier',
  explanation: 'Account numbers and bank transfer codes are not proof of fraud by themselves. An unexpected request to submit them should be checked through a known bank channel.',
  strength: 'weak',
}

const personalInformationRequest: TextRule = {
  id: 'personal-information-request',
  pattern: /\b(?:send|share|provide|enter|confirm|submit)\s+(?:your\s+)?(?:social security number|national id|identity number|date of birth|personal details|identity details|aadhaar(?: number)?|aadhar(?: number)?|pan(?: card)? number|tax id)\b/i,
  title: 'The message asks for sensitive personal details',
  explanation: 'Unexpected requests for identity information should be verified through a known official channel.',
  strength: 'weak',
}

const kycSuspensionThreat: TextRule = {
  id: 'kyc-suspension-threat',
  pattern: /\b(?:kyc|identity verification|customer verification)\b.{0,55}\b(?:suspend(?:ed|sion)?|block(?:ed)?|disable(?:d)?|restrict(?:ed|ion)?|deactivat(?:e|ed|ion))\b|\b(?:suspend|block|disable|restrict|deactivate)\b.{0,45}\b(?:your\s+)?(?:kyc|identity verification|account)\b/i,
  title: 'The message threatens to suspend access over KYC verification',
  explanation: 'KYC requests can be legitimate, but a suspension threat should be verified using a known bank channel before you act.',
  strength: 'weak',
}

const kycAppInstallRequest: TextRule = {
  id: 'kyc-app-install-request',
  pattern: /\b(?:install|download)\b.{0,65}\b(?:app|application)\b.{0,65}\b(?:kyc|verify|verification|bank|account)\b|\b(?:kyc|verify|verification|bank|account)\b.{0,65}\b(?:install|download)\b.{0,65}\b(?:app|application)\b/i,
  title: 'The message instructs you to install an app for account or KYC verification',
  explanation: 'Unexpected app-install instructions can expose account or device information. Find the bank’s official app independently instead of following a message link.',
  strength: 'weak',
}

const recoveryInstruction = /\b(?:sign[ -]?in|log[ -]?in|secure|restore|recover|unlock)\b.{0,55}\b(?:account|profile|banking|access)\b|\b(?:account|profile|banking|access)\b.{0,55}\b(?:sign[ -]?in|log[ -]?in|secure|restore|recover|unlock)\b/i

const paymentRequest: TextRule = {
  id: 'payment-request',
  pattern: /\b(?:pay|transfer|send|wire)\s+(?:the\s+)?(?:money|funds|fee|payment|deposit|gift cards?|cryptocurrency|crypto|a wire transfer)\b/i,
  title: 'The message asks you to send money or use an unusual payment method',
  explanation: 'Payment requests can be legitimate, but transfers and gift-card or cryptocurrency payments may be difficult to reverse.',
  strength: 'weak',
}

const deliveryFeeRequest: TextRule = {
  id: 'delivery-fee-request',
  pattern: /\b(?:pay|send|transfer|submit|provide)\b.{0,35}\b(?:(?:a|an|the|small|minor|nominal|additional|extra)\s+){0,3}(?:re[ -]?delivery|redelivery|delivery|shipping)\s+(?:fee|charge)\b(?:\s+of\s+(?:rs\.?\s*)?\d+(?:\.\d{1,2})?)?/i,
  title: 'The message asks for a delivery or re-delivery payment',
  explanation: 'A small delivery fee can be legitimate, but an unexpected payment request linked to a parcel hold or short deadline should be verified with the delivery service through a channel you find independently.',
  strength: 'weak',
}

const deliveryHoldPattern = /\b(?:parcel|package|delivery|shipment)\b.{0,65}\b(?:on hold|held|could not be verified|cannot be verified|unverified|address.{0,20}(?:verify|verified|verification|confirm))\b|\b(?:on hold|held|could not be verified|cannot be verified|unverified)\b.{0,65}\b(?:parcel|package|delivery|shipment|address)\b/i
const deliveryReturnThreatPattern = /\b(?:avoid|prevent)\s+(?:the\s+)?(?:parcel\s+)?return\b|\b(?:return|returned)\b.{0,30}\b(?:within|unless|if you do not|otherwise)\b/i

const transactionStatusAlert: TextRule = {
  id: 'transaction-status-alert',
  pattern: /\b(?:unauthori[sz]ed|unrecognized|unfamiliar|failed|declined)\b.{0,45}\b(?:transaction|payment|charge|transfer)\b|\b(?:transaction|payment|charge|transfer)\b.{0,45}\b(?:unauthori[sz]ed|unrecognized|unfamiliar|failed|declined)\b/i,
  title: 'The message reports a failed or unrecognized transaction',
  explanation: 'Payment alerts can be genuine or mistaken. Check the transaction in your bank’s official app or through a contact method you already trust.',
  strength: 'informational',
}

const refundStatusNotification: TextRule = {
  id: 'refund-status-notification',
  pattern: /\brefund\b.{0,35}\b(?:has been|was|is|will be)\s+(?:successfully\s+)?(?:processed|issued|sent|initiated|approved|completed|credited)\b|\b(?:successfully\s+)?(?:processed|issued|sent|initiated|approved|completed|credited)\s+(?:your\s+)?refund\b|\brefund\b.{0,35}\bon its way\b/i,
  title: 'The message reports a refund status',
  explanation: 'A refund status by itself is not a warning. Check it against the original purchase or the merchant’s official channel if it was unexpected.',
  strength: 'informational',
}

const refundReleaseFeeRequest: TextRule = {
  id: 'refund-release-fee-request',
  pattern: /\b(?:pay|send|transfer|submit|provide|make)\b.{0,45}\b(?:(?:an?|the|additional|extra|upfront)\s+){0,2}(?:(?:processing|release|service|handling|recovery)\s+)?(?:fee|charge|payment|amount|money|funds|transfer|deposit|\$?\d+(?:\.\d{2})?)\b.{0,75}\b(?:refund|release|receive|recover|reversal|money back|funds)\b|\b(?:pay|send|transfer|submit|provide|make)\b.{0,45}\b(?:(?:your|an?)\s+)?security deposits?\b.{0,75}\b(?:refund|release|receive|recover|reversal|money back|funds)\b|\b(?:refund|reversal|recover(?:y|ing)?(?:\s+(?:your\s+)?(?:money|funds))?|money back|release (?:your\s+)?funds)\b.{0,65}\b(?:pay|send|transfer|submit|provide|make)\b.{0,45}\b(?:fee|charge|payment|amount|money|funds|transfer|deposit|security deposits?)\b/i,
  title: 'The message asks for a payment to release or recover money',
  explanation: 'A request to pay an added fee or amount to release a refund or recover funds deserves independent verification. Do not rely on contact details supplied in the message.',
  strength: 'strong',
}

const transactionReversalCredentialRequest: TextRule = {
  id: 'transaction-reversal-credential-request',
  pattern: /\b(?:send|share|provide|enter|submit|confirm)\b.{0,35}\b(?:your\s+)?(?:otp|one[- ]time code|verification code|security code|password|passcode|pin)\b.{0,65}\b(?:reverse|reversal|cancel|undo|stop|release|recover|process)\b.{0,45}\b(?:unauthori[sz]ed\s+)?(?:transaction|payment|transfer|debit|refund)\b|\b(?:reverse|reversal|cancel|undo|stop|release|recover|process)\b.{0,45}\b(?:unauthori[sz]ed\s+)?(?:transaction|payment|transfer|debit|refund)\b.{0,75}\b(?:send|share|provide|enter|submit|confirm)\b.{0,35}\b(?:your\s+)?(?:otp|one[- ]time code|verification code|security code|password|passcode|pin)\b/i,
  title: 'The message asks for an authentication detail to change a transaction or refund',
  explanation: 'A one-time code, PIN, or password should not be shared to release a refund, reverse a transaction, or cancel a debit. Contact your bank through a known channel instead.',
  strength: 'strong',
}

const refundPaymentVerificationRequest: TextRule = {
  id: 'refund-payment-verification-request',
  pattern: /\brefund\b.{0,65}\b(?:cannot|can not|will not|won't|unable to|not able to)\b.{0,45}\b(?:processed|issued|released|paid|completed)\b.{0,65}\b(?:complete|perform|finish|confirm|verify)\b.{0,35}\bpayment verification\b|\b(?:complete|perform|finish|confirm|verify)\b.{0,35}\bpayment verification\b.{0,65}\brefund\b/i,
  title: 'The message says payment verification is needed for a refund',
  explanation: 'A request to complete payment verification before a refund is processed should be checked through the merchant or bank using a known channel. This finding does not mean credentials were requested.',
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
const prizeClaimRelationPattern = /\b(?:claim|redeem|collect|receive|release)\b/i
const prizeFeePattern = /\b(?:pay|send|transfer|cover|submit)\b.{0,35}\b(?:processing|administrative|admin|delivery|release|claim|tax)\s+fees?\b|\b(?:processing|administrative|admin|delivery|release|claim|tax)\s+fees?\b.{0,35}\b(?:prize|lottery|winnings|reward|draw)\b/i
const prizeAdditionalPaymentPattern = /\b(?:pay|send|transfer|submit|make)\b.{0,35}\b(?:an?\s+)?(?:additional|extra|another)\s+(?:payment|amount|transfer)\b|\b(?:additional|extra|another)\s+(?:payment|amount|transfer)\b.{0,35}\b(?:claim|collect|receive|redeem|release)\b/i
const maintenanceAccountFeePaymentPattern = /\b(?:pay|send|transfer|submit|provide)\b.{0,35}\b(?:a\s+|an\s+|the\s+)?(?:service|maintenance|restoration|reactivation)?\s*(?:fee|charge|payment)\b.{0,65}\b(?:restore|unlock|reactivate|recover|reinstate|access|account)\b/i
const authorityPattern = /\b(?:your\s+)?(?:manager|boss|supervisor|director|executive|ceo|chief executive|owner|president)\b/i
const giftCardMentionPattern = /\bgift cards?\b/i
const giftCardValueRequestPattern = /\b(?:send|share|text|email|provide|give|forward|upload)\b.{0,65}\b(?:gift cards?|(?:redemption\s+)?codes?)\b|\bgift cards?\b.{0,45}\b(?:codes?|redemption codes?)\b/i
const giftCardPhotoRequestPattern = /\b(?:send|share|text|email|provide|give|forward|upload|take)\b.{0,65}\b(?:photos?|pictures?|images?)\b.{0,45}\bgift cards?\b|\bgift cards?\b.{0,65}\b(?:photos?|pictures?|images?)\b/i
const giftCardRequestPattern = /\b(?:buy|purchase|order|get|pick up|send|share|text|email|provide|give|forward|upload)\b.{0,65}\bgift cards?\b|\bgift cards?\b.{0,65}\b(?:codes?|redemption codes?|photos?|pictures?|images?)\b/i
const urlPattern = /(?:https?:\/\/|www\.)[^\s<>"']+/i

const detectionRules = [
  authenticationRequest,
  accountSecurityAlert,
  accountThreat,
  kycExpiration,
  kycSuspensionThreat,
  bankingDetailsRequest,
  bankingIdentifierRequest,
  kycAppInstallRequest,
  personalInformationRequest,
  transactionStatusAlert,
  refundStatusNotification,
  refundReleaseFeeRequest,
  transactionReversalCredentialRequest,
  refundPaymentVerificationRequest,
  paymentRequest,
  deliveryFeeRequest,
  giftCardPurchaseRequest,
] satisfies readonly TextRule[]

function splitSentences(text: string, splitOnLineBreaks = true, splitOnColons = true): string[] {
  const trimmed = maskReportedQuotes(text.trim())
  const quoteClosers: Record<string, string> = { '"': '"', "'": "'", '“': '”', '‘': '’' }
  const firstCharacter = trimmed[0]
  if (firstCharacter && quoteClosers[firstCharacter] && trimmed.endsWith(quoteClosers[firstCharacter])) {
    return splitSentences(trimmed.slice(1, -1))
  }

  const closingQuotes: string[] = []
  const boundaries: Array<{ end: number; next: number }> = []
  const isWordCharacter = (character: string | undefined) => Boolean(character && /[\p{L}\p{N}]/u.test(character))

  for (let index = 0; index < trimmed.length; index += 1) {
    const character = trimmed[index] ?? ''
    const previousCharacter = trimmed[index - 1]
    const nextCharacter = trimmed[index + 1]

    if (character === "'" && isWordCharacter(previousCharacter) && isWordCharacter(nextCharacter)) continue

    if (closingQuotes.length > 0) {
      if (character === closingQuotes[closingQuotes.length - 1]) {
        closingQuotes.pop()
      } else if (quoteClosers[character]) {
        closingQuotes.push(quoteClosers[character])
      }
      continue
    }

    if (character === "'" && isWordCharacter(previousCharacter) && !isWordCharacter(nextCharacter)) continue

    if (quoteClosers[character]) {
      closingQuotes.push(quoteClosers[character])
      continue
    }

    const isLineBreak = character === '\n' || character === '\r'
    const continuesPassiveAuthentication = character === ':'
      && /\b(?:requires?|needs?)\s+(?:your|an?)$/iu.test(trimmed.slice(Math.max(0, index - 24), index))
      && /^\s*(?:otp|one[- ]time code|verification code|security code|password|passcode|pin)\b/iu.test(trimmed.slice(index + 1))
    const isCurrencyAbbreviation = character === '.'
      && /\brs$/iu.test(trimmed.slice(Math.max(0, index - 5), index))
      && /^\s*\d/u.test(trimmed.slice(index + 1))
    const isDelimiter = (/[.!?;]/u.test(character) && !isCurrencyAbbreviation)
      || (splitOnColons && character === ':' && !continuesPassiveAuthentication)
      || (splitOnLineBreaks && isLineBreak)
    const endsAtBoundary = (splitOnLineBreaks && isLineBreak)
      || index === trimmed.length - 1
      || /\s/u.test(nextCharacter ?? '')
    if (isDelimiter && endsAtBoundary) {
      let nextIndex = index + 1
      while (trimmed[nextIndex] === '\n' || trimmed[nextIndex] === '\r') nextIndex += 1
      boundaries.push({ end: index, next: nextIndex })
      index = nextIndex - 1
      continue
    }

    const contrast = trimmed.slice(index).match(/^\s+(?:but|however|instead|yet)\b\s+/iu)
    if (contrast) {
      boundaries.push({ end: index, next: index + contrast[0].length })
      index += contrast[0].length - 1
    }
  }

  const sentences: string[] = []
  let sentenceStart = 0
  for (const boundary of boundaries) {
    const sentence = trimmed.slice(sentenceStart, boundary.end).trim()
    if (sentence) sentences.push(sentence)
    sentenceStart = boundary.next
  }
  const finalSentence = trimmed.slice(sentenceStart).trim()
  if (finalSentence) sentences.push(finalSentence)

  return sentences.map((sentence) => sentence.trim()).filter(Boolean)
}

/** Masks only quotations introduced as reported or educational examples.
 * Raw quoted content remains analyzable. An unmatched opening quote is left
 * untouched so malformed input cannot hide the remainder of the message.
 */
function maskReportedQuotes(text: string): string {
  const quoteClosers: Record<string, string> = { '"': '"', "'": "'", '“': '”', '‘': '’' }
  const characters = text.split('')
  const isWordCharacter = (character: string | undefined) => Boolean(character && /[\p{L}\p{N}]/u.test(character))

  for (let index = 0; index < characters.length; index += 1) {
    const opening = characters[index] ?? ''
    if (!quoteClosers[opening]) continue
    if (opening === "'" && isWordCharacter(characters[index - 1]) && isWordCharacter(characters[index + 1])) continue
    if (opening === "'" && isWordCharacter(characters[index - 1]) && !isWordCharacter(characters[index + 1])) continue

    const closing = quoteClosers[opening]
    const stack = [closing]
    let end = index + 1
    for (; end < characters.length && stack.length > 0; end += 1) {
      const current = characters[end] ?? ''
      if (current === "'" && isWordCharacter(characters[end - 1]) && isWordCharacter(characters[end + 1])) continue
      if (current === stack[stack.length - 1]) stack.pop()
      else if (quoteClosers[current]) stack.push(quoteClosers[current] ?? current)
    }
    if (stack.length > 0) continue

    const prefix = text.slice(0, index)
    const introducedAsReported = /\b(?:said|says|reads|read|wrote|writes)\s*:\s*$/iu.test(prefix)
    const introducedAsExample = /\b(?:educational\s+examples?(?:\s+of\s+(?:a\s+)?(?:refund\s+)?(?:scams?|phishing|fraud))?|examples?\s+of\s+(?:a\s+)?(?:scam|phishing|fraud)|(?:scam|phishing|fraud)\s+awareness|warning\s+about\s+(?:scams?|phishing|fraud)|another\s+(?:scam\s+)?example)\s*:\s*$/iu.test(prefix)
      || /\b(?:be careful|beware|watch out)\s+of\s+(?:these\s+)?(?:scam\s+)?(?:messages|texts|emails)(?:\s+(?:saying|asking|that say|which say))?\s*:\s*$/iu.test(prefix)
      || /\b(?:scammers?|fraudsters?)\s+(?:may|might|often|will)\s+ask\s*:\s*$/iu.test(prefix)
    const suffixEnd = [text.indexOf('.', end), text.indexOf('!', end), text.indexOf('?', end), text.indexOf(';', end), text.indexOf('\n', end)].filter((position) => position >= 0)
    const suffix = text.slice(end, suffixEnd.length ? Math.min(...suffixEnd) : text.length)
    const reportedDiscussion = /\b(?:looks? suspicious|is suspicious|is an example|is a scam|is phishing|was a scam|is being discussed)\s*:\s*$/iu.test(prefix)
      || (/\b(?:the|this)\s+(?:text|message|email)\s*$/iu.test(prefix) && /^\s*(?:looks? suspicious|is suspicious|is a scam|is phishing)\b/iu.test(suffix))
    if (!introducedAsReported && !introducedAsExample && !reportedDiscussion) {
      index = end - 1
      continue
    }

    for (let cursor = index; cursor < end; cursor += 1) characters[cursor] = ' '
    index = end - 1
  }
  return characters.join('')
}

function isSafetyOrEducationalContext(sentence: string): boolean {
  return /\b(?:be careful|beware|watch out)\s+of\s+(?:these\s+)?(?:scam\s+)?(?:messages|texts|emails)(?:\s+(?:saying|asking|that say|which say))?\b/i.test(sentence)
    || /\b(?:example\s+(?:of\s+(?:a\s+)?)?(?:scam|phishing|fraud)|(?:scam|phishing|fraud)\s+awareness|educational\s+(?:examples?|warnings?)(?:\s+of\s+(?:a\s+)?(?:refund\s+)?(?:scams?|phishing|fraud))?|(?:scam|phishing|fraud)\s+examples?|warning\s+about\s+(?:scams?|phishing|fraud))\b/i.test(sentence)
    || /\b(?:scammers?|fraudsters?)\s+(?:may|might|often|will)\s+(?:ask|say|claim|promise|tell(?:\s+you)?)\b/i.test(sentence)
}

function hasNearbyNegation(sentence: string, matchIndex: number): boolean {
  const precedingText = sentence.slice(Math.max(0, matchIndex - 32), matchIndex)
  return /\b(?:never|don't|do not|shouldn't|should not|must not|avoid|not to|won't|will not|is not|isn't|not be)\s+(?:(?:you|we|they)\s+)?(?:please\s+)?$/i.test(precedingText)
    || /\b(?:avoid|never|don't|do not|shouldn't|should not|must not)\s+(?:sharing|sending|providing|entering|submitting|confirming)\s+(?:your\s+)?$/i.test(precedingText)
    || /\b(?:does not|doesn't|do not|don't|never)\s+(?:require|requires|need|needs|request|requests)\b.{0,18}$/i.test(precedingText)
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
  const matchingText = sentence.replace(/[\r\n\u2028\u2029]/gu, ' ')
  for (const match of matchingText.matchAll(globalPattern)) {
    if (match.index === undefined || hasNearbyNegation(matchingText, match.index)) continue
    if (pattern === authenticationRequest.pattern) {
      const secretOffset = match[0].search(/\b(?:otp|one[- ]time code|verification code|security code|password|passcode|pin|credentials?)\b/i)
      if (secretOffset >= 0 && hasNearbyNegation(matchingText, match.index + secretOffset)) continue
    }
    return sentence.slice(match.index, match.index + match[0].length)
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

function hasAdjacentSignals(sentences: readonly string[], patterns: readonly RegExp[]): boolean {
  return sentences.some((sentence, index) => {
    const nextSentence = sentences[index + 1]
    if (!nextSentence) return false
    return patterns.every((pattern) => evidenceFor(sentence, pattern) || evidenceFor(nextSentence, pattern))
  })
}

function prizeRequestEvidence(sentences: readonly string[], requestPattern: RegExp): string | undefined {
  for (let index = 0; index < sentences.length; index += 1) {
    const sentence = sentences[index] ?? ''
    if (!evidenceFor(sentence, requestPattern) || !evidenceFor(sentence, prizeClaimRelationPattern)) continue

    const currentAwardContext = evidenceFor(sentence, prizeSelectionPattern)
      || evidenceFor(sentence, prizePattern)
      || evidenceFor(sentence, prizeContextPattern)
    const previousSentence = sentences[index - 1]
    const previousAwardContext = previousSentence
      && (evidenceFor(previousSentence, prizeSelectionPattern) || evidenceFor(previousSentence, prizePattern))
    if (!currentAwardContext && !previousAwardContext) continue

    return [previousAwardContext ? previousSentence : undefined, sentence].filter(Boolean).join(' · ')
  }
  return undefined
}

function routineMaintenanceWindow(sentence: string, sentences: readonly string[]): string {
  const index = sentences.indexOf(sentence)
  return [sentences[index - 1], sentence, sentences[index + 1]].filter(Boolean).join(' ')
}

function addRuleFindings(findings: Finding[], sentences: readonly string[], authenticationSentences: readonly string[]) {
  const activeSentences = sentences.filter((sentence) => !isSafetyOrEducationalContext(sentence))
  const hasAuthenticationRequest = authenticationSentences.some((sentence) =>
    !isSafetyOrEducationalContext(sentence) && evidenceFor(sentence, authenticationRequest.pattern),
  )
  const prizePaymentEvidence = prizeRequestEvidence(activeSentences, prizeFeePattern)
    ?? prizeRequestEvidence(activeSentences, prizeAdditionalPaymentPattern)
    ?? prizeRequestEvidence(activeSentences, bankingDetailsRequest.pattern)

  for (const rule of detectionRules) {
    if (findings.some((finding) => finding.id === rule.id)) continue
    const candidates = rule.id === authenticationRequest.id ? authenticationSentences : activeSentences
    for (const sentence of candidates) {
      if (isSafetyOrEducationalContext(sentence)) continue
      const evidence = evidenceFor(sentence, rule.pattern)
      if (!evidence) continue
      if (rule.id === refundReleaseFeeRequest.id
        && prizePaymentEvidence?.includes(sentence)
        && (evidenceFor(sentence, prizeFeePattern) || evidenceFor(sentence, prizeAdditionalPaymentPattern))) continue

      const maintenanceWindow = routineMaintenanceWindow(sentence, activeSentences)
      const scheduledMaintenance = /\b(?:scheduled|planned|routine)\s+(?:bank(?:ing)?\s+)?maintenance\b/i.test(maintenanceWindow)
      const temporaryRestriction = /\btemporar(?:y|ily)\b.{0,35}\b(?:restrict(?:ed|ion)?|lock(?:ed)?|block(?:ed)?|suspend(?:ed|sion)?)\b/i.test(maintenanceWindow)
      const trustedApp = /\b(?:trusted|official|secure)\s+(?:(?:bank|banking)\s+)?(?:app|application)\b|\b(?:bank's|banks')\s+(?:official\s+)?app\b|\b(?:banking|bank)\s+(?:app|application)\s+(?:we|you)\s+already\s+trust\b/i.test(maintenanceWindow)
      const hasExternalLink = urlPattern.test(maintenanceWindow)
      const hasUrgency = Boolean(evidenceFor(maintenanceWindow, urgencyPattern))
      const hasPaymentRequest = Boolean(evidenceFor(maintenanceWindow, paymentRequest.pattern)
        || evidenceFor(maintenanceWindow, refundReleaseFeeRequest.pattern)
        || evidenceFor(maintenanceWindow, prizeFeePattern)
        || /\b(?:pay|send|transfer|submit|provide)\b.{0,45}\b(?:fee|charge|payment|deposit|amount)\b/i.test(maintenanceWindow))
      const routineMaintenance = scheduledMaintenance && !hasExternalLink && !hasUrgency && !hasAuthenticationRequest && !hasPaymentRequest
      const restrictionIsPartOfMaintenance = /\b(?:scheduled|planned|routine)\s+(?:bank(?:ing)?\s+)?maintenance\b/i.test(sentence)
        && /\btemporar(?:y|ily)\b.{0,35}\b(?:restrict(?:ed|ion)?|lock(?:ed)?|block(?:ed)?|suspend(?:ed|sion)?)\b/i.test(sentence)
      const updateIsLinkedToMaintenance = /\b(?:during|after|when|once)\s+(?:the\s+)?(?:scheduled\s+)?maintenance\b|\b(?:after|when|once)\s+service\s+resumes\b/i.test(sentence)

      if ((rule.id === accountThreat.id || rule.id === kycSuspensionThreat.id)
        && restrictionIsPartOfMaintenance && routineMaintenance) continue
      if (rule.id === bankingDetailsRequest.id && trustedApp && updateIsLinkedToMaintenance && routineMaintenance && (temporaryRestriction || restrictionIsPartOfMaintenance)) continue

      findings.push({ ...rule, evidence })
      break
    }
  }

  if (!findings.some((finding) => finding.id === 'maintenance-access-fee-request')) {
    for (const sentence of activeSentences) {
      const maintenanceWindow = routineMaintenanceWindow(sentence, activeSentences)
      const hasScheduledRestriction = /\b(?:scheduled|planned|routine)\s+(?:bank(?:ing)?\s+)?maintenance\b/i.test(maintenanceWindow)
        && /\btemporar(?:y|ily)\b.{0,35}\b(?:restrict(?:ed|ion)?|lock(?:ed)?|block(?:ed)?|suspend(?:ed|sion)?)\b/i.test(maintenanceWindow)
      const evidence = hasScheduledRestriction ? evidenceFor(maintenanceWindow, maintenanceAccountFeePaymentPattern) : undefined
      if (!evidence) continue

      findings.push({
        id: 'maintenance-access-fee-request',
        title: 'The message asks for a fee to restore account access',
        explanation: 'A fee request linked to restoring account access deserves an independent check, even when the message describes scheduled maintenance.',
        strength: 'weak',
        evidence,
      })
      break
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
      || evidenceFor(sentence, deliveryFeeRequest.pattern)
      || (urlPattern.test(sentence) && evidenceFor(sentence, verificationRequest))
  })

  if (urgencySentence && !findings.some((finding) => finding.id === 'contextual-urgency')) {
    findings.push({
      id: 'contextual-urgency',
      title: 'Time pressure is paired with a request for action',
      explanation: 'A short deadline deserves closer attention when paired with an account, information, payment, or delivery request.',
      strength: 'weak',
      evidence: evidenceFor(urgencySentence, urgencyPattern),
    })
  }

  const deliveryPaymentIndex = activeSentences.findIndex((sentence, index) => {
    const nearby = [activeSentences[index - 1], sentence, activeSentences[index + 1]].filter(Boolean).join(' ')
    return evidenceFor(sentence, deliveryFeeRequest.pattern)
      && (evidenceFor(nearby, deliveryHoldPattern) || evidenceFor(nearby, deliveryReturnThreatPattern))
  })
  if (deliveryPaymentIndex >= 0 && !findings.some((finding) => finding.id === 'delivery-hold-payment-combination')) {
    const evidence = [activeSentences[deliveryPaymentIndex - 1], activeSentences[deliveryPaymentIndex], activeSentences[deliveryPaymentIndex + 1]]
      .filter((sentence): sentence is string => Boolean(sentence))
      .filter((sentence) => evidenceFor(sentence, deliveryFeeRequest.pattern) || evidenceFor(sentence, deliveryHoldPattern) || evidenceFor(sentence, deliveryReturnThreatPattern))
      .slice(0, 2)
      .join(' · ')
    findings.push({
      id: 'delivery-hold-payment-combination',
      title: 'A parcel warning is paired with a delivery payment request',
      explanation: 'A parcel hold or return warning combined with a request for a delivery payment should be verified with the carrier through contact details you find independently.',
      strength: 'weak',
      evidence,
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

  const accountSecurityLink = hasAdjacentSignals(activeSentences, [accountSecurityAlert.pattern, recoveryInstruction, urlPattern])
    || hasAdjacentSignals(activeSentences, [accountSecurityAlert.pattern, bankingDetailsRequest.pattern, urlPattern])
    || hasAdjacentSignals(activeSentences, [accountSecurityAlert.pattern, bankingIdentifierRequest.pattern, urlPattern])
  if (accountSecurityLink && !findings.some((finding) => finding.id === 'account-security-link-combination')) {
    const evidence = activeSentences
      .filter((sentence, index) => {
        const adjacent = [sentence, activeSentences[index + 1]].filter(Boolean).join(' ')
        return evidenceFor(adjacent, accountSecurityAlert.pattern)
          || evidenceFor(adjacent, recoveryInstruction)
          || evidenceFor(adjacent, urlPattern)
      })
      .slice(0, 2)
      .join(' · ')
    findings.push({
      id: 'account-security-link-combination',
      title: 'An account security alert is paired with an online action',
      explanation: 'A security alert followed by a sign-in, recovery, or banking request through a message link deserves a separate check. The review cannot verify the sender or destination.',
      strength: 'weak',
      evidence: evidence.slice(0, 240) || activeText.slice(0, 160),
    })
  }

  const kycSensitiveRequest = hasRelatedSignals(activeSentences, [kycSuspensionThreat.pattern, personalInformationRequest.pattern, urlPattern])
    || hasRelatedSignals(activeSentences, [kycSuspensionThreat.pattern, bankingIdentifierRequest.pattern, urlPattern])
    || hasRelatedSignals(activeSentences, [kycSuspensionThreat.pattern, kycAppInstallRequest.pattern, urlPattern])
  if (kycSensitiveRequest && !findings.some((finding) => finding.id === 'kyc-impersonation-combination')) {
    const evidence = activeSentences.find((sentence) =>
      evidenceFor(sentence, kycSuspensionThreat.pattern) || evidenceFor(sentence, personalInformationRequest.pattern) || evidenceFor(sentence, bankingIdentifierRequest.pattern) || evidenceFor(sentence, kycAppInstallRequest.pattern) || evidenceFor(sentence, urlPattern),
    )
    findings.push({
      id: 'kyc-impersonation-combination',
      title: 'A KYC suspension threat is paired with a linked information or app request',
      explanation: 'A KYC threat combined with a link to submit sensitive details or install an app is a strong warning pattern. Verify through a contact method you already trust.',
      strength: 'strong',
      highConcernTrigger: 'contextual-combination',
      evidence: evidence?.slice(0, 160) || activeText.slice(0, 160),
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

  const prizeFeeEvidence = prizeRequestEvidence(activeSentences, prizeFeePattern)
    ?? prizeRequestEvidence(activeSentences, prizeAdditionalPaymentPattern)
  const prizeBankingEvidence = prizeRequestEvidence(activeSentences, bankingDetailsRequest.pattern)
  const prizeFeeCombination = Boolean(prizeFeeEvidence)
  const prizeBankingCombination = Boolean(prizeBankingEvidence)
  if ((prizeFeeCombination || prizeBankingCombination) && !findings.some((finding) => finding.id === 'prize-claim-payment-combination')) {
    findings.push({
      id: 'prize-claim-payment-combination',
      title: prizeFeeCombination
        ? 'A prize claim is paired with a processing or release fee'
        : 'A prize claim is paired with a banking information request',
      explanation: 'Requests for a fee or banking details to release a prize deserve independent verification. This pattern alone does not verify who sent the message.',
      strength: 'strong',
      highConcernTrigger: 'contextual-combination',
      evidence: (prizeFeeEvidence ?? prizeBankingEvidence)?.slice(0, 240) || activeText.slice(0, 160),
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
  const authenticationSentences = splitSentences(normalized, false, true)
  const activeText = sentences.filter((sentence) => !isSafetyOrEducationalContext(sentence)).join(' ')
  const findings: Finding[] = []

  addRuleFindings(findings, sentences, authenticationSentences)
  const credentialFinding = findings.find((finding) => finding.id === authenticationRequest.id)
  const transactionCredentialFinding = findings.find((finding) => finding.id === transactionReversalCredentialRequest.id)
  if (credentialFinding && transactionCredentialFinding) {
    credentialFinding.explanation = 'The message asks for an authentication secret in connection with a transaction or refund. Never share a one-time code, PIN, or password to reverse, release, or cancel a payment; contact your bank through a known channel.'
    findings.splice(findings.indexOf(transactionCredentialFinding), 1)
  }
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
