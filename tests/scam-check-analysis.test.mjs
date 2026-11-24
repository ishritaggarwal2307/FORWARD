import assert from 'node:assert/strict'
import test from 'node:test'
import { analyzeMessage } from '../src/features/scam-check/analysis/analyzeText.ts'
import { analyzeUrl } from '../src/features/scam-check/analysis/analyzeUrl.ts'
import {
  analyzeExtractedScreenshotText,
  analyzeScreenshot,
} from '../src/features/scam-check/analysis/analyzeScreenshot.ts'

const readableImageInspector = async () => ({ width: 800, height: 600 })

test('direct OTP request is high concern and includes explainable evidence', () => {
  const result = analyzeMessage('Your account is locked. Send your verification code immediately.')

  assert.equal(result.inputMode, 'message')
  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request' && finding.strength === 'strong'))
  assert.ok(result.findings.every((finding) => finding.evidence))
})

test('OTP safety advice does not trigger an authentication request', () => {
  const result = analyzeMessage('Never share your OTP with anyone.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'credentials-request'))
})

test('account suspension is a weak warning without a sensitive detail request', () => {
  const result = analyzeMessage('Your bank account will be blocked unless you contact support.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'account-access-threat' && finding.strength === 'weak'))
})

test('KYC expiration alone remains informational', () => {
  const result = analyzeMessage('Your KYC verification expires on 30 June. Please visit a branch if you have questions.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'kyc-expiration-mentioned' && finding.strength === 'informational'))
})

test('KYC expiration with an unexpected verification link raises warning signs, not high concern', () => {
  const result = analyzeMessage('Your KYC verification has expired. Verify your account at https://example.com/verify.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'kyc-expiration-mentioned'))
  assert.ok(result.findings.some((finding) => finding.id === 'verification-link-with-request'))
})

test('account threat, expired KYC, and urgent banking update form a strong combination', () => {
  const result = analyzeMessage('Your bank account will be blocked because your KYC has expired. Update your banking information immediately.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'account-access-threat'))
  assert.ok(result.findings.some((finding) => finding.id === 'kyc-expiration-mentioned'))
  assert.ok(result.findings.some((finding) => finding.id === 'banking-details-request'))
  assert.ok(result.findings.some((finding) => finding.id === 'account-verification-combination' && finding.strength === 'strong'))
})

test('legitimate KYC reminder is not elevated to high concern', () => {
  const result = analyzeMessage('A reminder: please complete your KYC verification at your next branch visit. No online action is required.')

  assert.notEqual(result.riskLevel, 'high-concern')
  assert.ok(!result.findings.some((finding) => finding.id === 'account-verification-combination'))
})

test('gift card purchase and code-sharing request from a manager is high concern', () => {
  const result = analyzeMessage('Your manager needs you to buy gift cards and send the codes.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'gift-card-purchase-request' && finding.strength === 'weak'))
  assert.ok(result.findings.some((finding) => finding.id === 'gift-card-value-request' && finding.strength === 'strong'))
  assert.ok(result.findings.some((finding) => finding.id === 'gift-card-request-combination' && finding.highConcernTrigger === 'contextual-combination'))
})

test('gift card purchase request without authority or urgency is a warning, not high concern', () => {
  const result = analyzeMessage('Please buy gift cards for the office thank-you event.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'gift-card-purchase-request'))
  assert.ok(!result.findings.some((finding) => finding.id === 'gift-card-request-combination'))
})

test('a workplace gift-card purchase without value transfer is not high concern', () => {
  const result = analyzeMessage('Your manager asked me to buy gift cards for the office event.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'gift-card-purchase-request'))
  assert.ok(!result.findings.some((finding) => finding.id === 'gift-card-request-combination'))
})

test('request for gift card photos identifies transferable value', () => {
  const result = analyzeMessage('Please send a photo of the gift cards and their redemption codes.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'gift-card-value-request' && finding.strength === 'strong'))
})

test('urgent gift card code transfer is high concern', () => {
  const result = analyzeMessage('Buy gift cards immediately and send me the redemption codes right away.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'contextual-urgency'))
  assert.ok(result.findings.some((finding) => finding.id === 'gift-card-request-combination'))
})

test('a secret gift-card code transfer is high concern', () => {
  const result = analyzeMessage('Please buy gift cards and send the redemption codes while keeping this request confidential.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'gift-card-value-request'))
  assert.ok(result.findings.some((finding) => finding.id === 'gift-card-request-combination'))
})

test('educational and ordinary gift card discussions do not trigger scam findings', () => {
  const educational = analyzeMessage('Scam awareness: scammers may ask you to buy gift cards and share the codes.')
  const ordinary = analyzeMessage('I bought gift cards for my nieces last weekend.')
  const generalDiscussion = analyzeMessage('Gift cards are popular birthday presents and easy to wrap.')

  assert.equal(educational.riskLevel, 'no-obvious-warning-signs')
  assert.equal(educational.findings.length, 0)
  assert.equal(ordinary.riskLevel, 'no-obvious-warning-signs')
  assert.equal(ordinary.findings.length, 0)
  assert.equal(generalDiscussion.riskLevel, 'no-obvious-warning-signs')
  assert.equal(generalDiscussion.findings.length, 0)
})

test('unexpected prize selection with a registration request is a weak warning', () => {
  const result = analyzeMessage('You have been selected for a prize draw; register to learn more.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'unexpected-prize-selection' && finding.strength === 'weak'))
})

test('general promotional prize announcement is not automatically suspicious', () => {
  const result = analyzeMessage('Join our summer prize draw. Register today for a chance to win a gift card.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'unexpected-prize-selection'))
})

test('prize processing fee request creates a high-concern combination', () => {
  const result = analyzeMessage('Pay a processing fee to claim your lottery winnings.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'prize-claim-payment-combination'))
})

test('a selected prize followed by registration and a release fee is high concern', () => {
  const result = analyzeMessage('You have been selected for a prize draw. Register to claim it and pay a release fee.')
  const finding = result.findings.find((item) => item.id === 'prize-claim-payment-combination')

  assert.equal(result.riskLevel, 'high-concern')
  assert.equal(finding?.strength, 'strong')
  assert.equal(finding?.highConcernTrigger, 'contextual-combination')
  assert.match(finding?.evidence ?? '', /selected for a prize draw/i)
  assert.match(finding?.evidence ?? '', /pay a release fee/i)
})

test('a selected prize claim paired with a processing fee is high concern', () => {
  const result = analyzeMessage('You were selected for a prize draw. Register to claim your reward and pay the processing fee.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'prize-claim-payment-combination' && /processing fee/i.test(finding.evidence ?? '')))
})

test('a prize additional-payment request is not mislabeled as a refund payment', () => {
  const result = analyzeMessage('You have been selected for a prize draw. Register to claim your reward and send an additional payment to receive it.')
  const prizeFinding = result.findings.filter((finding) => finding.id === 'prize-claim-payment-combination')

  assert.equal(result.riskLevel, 'high-concern')
  assert.equal(prizeFinding.length, 1)
  assert.equal(prizeFinding[0]?.strength, 'strong')
  assert.equal(prizeFinding[0]?.highConcernTrigger, 'contextual-combination')
  assert.match(prizeFinding[0]?.evidence ?? '', /additional payment/i)
  assert.ok(!result.findings.some((finding) => finding.id === 'refund-release-fee-request'))
})

test('an additional payment required to receive a selected prize is high concern', () => {
  const result = analyzeMessage('You have been selected for a prize draw. Register to claim your reward and send an additional payment to receive it.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'prize-claim-payment-combination'))
})

test('a prize selection paired with banking details to receive the reward is high concern', () => {
  const result = analyzeMessage('You have been selected for a prize draw. Register to claim it and update your banking information to receive the reward.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'prize-claim-payment-combination' && /banking information/i.test(finding.evidence ?? '')))
})

test('workplace raffles, event registration, and prize-scam education do not create a strong prize finding', () => {
  const examples = [
    'Our workplace raffle is open for the holiday party. Register to attend the event.',
    'Register for the charity event and pay the standard entry fee at the venue.',
    'Scam awareness: fraudsters may claim you won a prize and ask you to pay a release fee.',
    'Join our summer prize draw. Register today for a chance to win a gift card.',
  ]

  for (const example of examples) {
    const result = analyzeMessage(example)
    assert.ok(!result.findings.some((finding) => finding.id === 'prize-claim-payment-combination'), example)
    assert.notEqual(result.riskLevel, 'high-concern', example)
  }
})

test('a prize selection does not combine with an unrelated fee in a separate message topic', () => {
  const result = analyzeMessage('You have been selected for a prize draw. Separately, register for payroll and pay the annual service fee.')

  assert.notEqual(result.riskLevel, 'high-concern')
  assert.ok(!result.findings.some((finding) => finding.id === 'prize-claim-payment-combination'))
})

test('banking information requested to claim a prize is high concern', () => {
  const result = analyzeMessage('You won a prize. Update your banking information to receive your reward.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'banking-details-request'))
  assert.ok(result.findings.some((finding) => finding.id === 'prize-claim-payment-combination'))
})

test('routine bank branch instruction is not a warning', () => {
  const result = analyzeMessage('Please update your banking information at your nearest branch.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'banking-details-request'))
})

test('banking information requested through an unexpected link remains a warning', () => {
  const result = analyzeMessage('Please update your banking information using this link https://bank.example/update.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'banking-details-request'))
  assert.ok(result.findings.some((finding) => finding.id === 'verification-link-with-request'))
})

test('urgency with a banking information request raises warning signs', () => {
  const result = analyzeMessage('Update your banking information immediately.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'banking-details-request'))
  assert.ok(result.findings.some((finding) => finding.id === 'contextual-urgency'))
})

test('account threat with an offline branch instruction does not become a strong banking combination', () => {
  const result = analyzeMessage('Your account will be blocked. Update your banking information at your nearest branch.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'account-access-threat'))
  assert.ok(!result.findings.some((finding) => finding.id === 'account-verification-combination'))
})

test('routine account maintenance and a trusted-app update are not high concern', () => {
  const result = analyzeMessage('Your account will be temporarily locked for scheduled maintenance. Update your banking information in our secure app when service resumes.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'account-access-threat'))
  assert.ok(!result.findings.some((finding) => finding.id === 'banking-details-request'))
  assert.ok(!result.findings.some((finding) => finding.id === 'account-verification-combination'))
})

test('scheduled maintenance with a temporary account restriction is not a warning by itself', () => {
  const result = analyzeMessage('Your account will be temporarily restricted during scheduled maintenance. Use our trusted banking app to update contact details after service resumes.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => ['account-access-threat', 'kyc-suspension-threat', 'banking-details-request'].includes(finding.id)))
})

test('maintenance wording does not suppress an unrelated account threat', () => {
  const result = analyzeMessage('Scheduled bank maintenance is planned for Sunday. Separately, your account will be temporarily restricted next month.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'account-access-threat'))
})

test('routine trusted-app maintenance wording does not suppress a fee request', () => {
  const result = analyzeMessage('Your account will be temporarily restricted during scheduled maintenance. Pay a service fee to restore access through our trusted app.')

  assert.notEqual(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'account-access-threat' || finding.id === 'kyc-suspension-threat'))
})

test('a maintenance service fee is identified without a refund-fee finding or high escalation', () => {
  const result = analyzeMessage('Your account will be temporarily restricted during scheduled maintenance. Pay a service fee to restore access through our trusted app.')
  const finding = result.findings.find((item) => item.id === 'maintenance-access-fee-request')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((item) => item.id === 'account-access-threat'))
  assert.equal(finding?.strength, 'weak')
  assert.match(finding?.evidence ?? '', /pay a service fee to restore access/i)
  assert.ok(!result.findings.some((item) => item.id === 'refund-release-fee-request'))
  assert.ok(!result.findings.some((item) => item.highConcernTrigger))
})

test('scheduled-maintenance language does not suppress urgent banking instructions', () => {
  const result = analyzeMessage('Your account will be temporarily restricted during scheduled maintenance. Update your banking information immediately in our trusted app.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'banking-details-request'))
  assert.ok(result.findings.some((finding) => finding.id === 'contextual-urgency'))
})

test('unrelated account-threat and banking-update sentences do not combine into high concern', () => {
  const result = analyzeMessage('Your bank account will be blocked next month. Separately, update banking information for payroll using the company app.')

  assert.notEqual(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'account-access-threat'))
  assert.ok(result.findings.some((finding) => finding.id === 'banking-details-request'))
  assert.ok(!result.findings.some((finding) => finding.id === 'account-verification-combination'))
})

test('routine bank account notification is not elevated by account terminology alone', () => {
  const result = analyzeMessage('Your monthly account statement is ready to view in the bank app.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
})

test('a new-device account alert is informational and not high concern', () => {
  const result = analyzeMessage('A new device login was detected for your account. If this was you, no action is needed.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'account-security-alert' && finding.strength === 'informational'))
  assert.ok(!result.findings.some((finding) => finding.highConcernTrigger))
})

test('suspicious login, unauthorized activity, and account takeover wording is recognized as an alert', () => {
  const examples = [
    'A suspicious login attempt was detected for your account.',
    'Unauthorized account activity was detected on your profile.',
    'An account takeover was detected on your online banking profile.',
  ]

  for (const example of examples) {
    const result = analyzeMessage(example)
    assert.ok(result.findings.some((finding) => finding.id === 'account-security-alert'), example)
    assert.notEqual(result.riskLevel, 'high-concern', example)
  }
})

test('an account compromise followed by a linked recovery instruction is flagged without claiming verification', () => {
  const result = analyzeMessage('Your account was compromised. Sign in to restore access at https://example.com/login.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'account-security-alert'))
  assert.ok(result.findings.some((finding) => finding.id === 'account-security-link-combination'))
  assert.match(result.findings.find((finding) => finding.id === 'account-security-link-combination')?.explanation ?? '', /cannot verify/i)
})

test('unauthorized account access followed by an OTP request remains high concern', () => {
  const result = analyzeMessage('Unauthorized access to your account was detected. Share your OTP to block it.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'account-security-alert'))
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
})

test('account numbers and IFSC codes without a request do not trigger findings', () => {
  const result = analyzeMessage('My bank account number is 1234567890 and the IFSC code is ABCD0123456.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
})

test('a request for an account number and IFSC through a link is a warning, not automatically high concern', () => {
  const result = analyzeMessage('Submit your bank account number and IFSC code through https://example.com/verify.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'banking-identifier-request'))
  assert.ok(!result.findings.some((finding) => finding.highConcernTrigger))
})

test('direct net-banking password requests retain high-concern treatment', () => {
  const result = analyzeMessage('Share your net banking password with support to restore access.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request' && finding.highConcernTrigger === 'direct-authentication'))
})

test('KYC suspension threats paired with identity details and a link are high concern', () => {
  const result = analyzeMessage('Your KYC will be suspended unless you submit your Aadhaar number at https://example.com/kyc.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'kyc-suspension-threat'))
  assert.ok(result.findings.some((finding) => finding.id === 'personal-information-request'))
  assert.ok(result.findings.some((finding) => finding.id === 'kyc-impersonation-combination'))
})

test('KYC app-install instructions are flagged for independent verification', () => {
  const result = analyzeMessage('Install this app to complete your KYC verification.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'kyc-app-install-request'))
  assert.ok(!result.findings.some((finding) => finding.highConcernTrigger))
})

test('a KYC suspension threat combined with an app link is high concern', () => {
  const result = analyzeMessage('Your KYC will be suspended unless you install this app to verify your account at https://example.com/app.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'kyc-impersonation-combination'))
})

test('a transaction confirmation remains an ordinary notification', () => {
  const result = analyzeMessage('Your card transaction of 500 rupees at the grocery store is complete.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
})

test('a failed payment notice is informational without a requested action', () => {
  const result = analyzeMessage('Your payment failed because the card was declined. No further action is needed.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'transaction-status-alert' && finding.strength === 'informational'))
})

test('an unauthorized transaction alert is informational by itself', () => {
  const result = analyzeMessage('An unauthorized transaction of 500 rupees was reported on your account.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'transaction-status-alert' && finding.strength === 'informational'))
  assert.ok(!result.findings.some((finding) => finding.highConcernTrigger))
})

test('a normal refund notification does not produce a warning', () => {
  const result = analyzeMessage('Your refund has been processed and should arrive in 5 to 7 business days.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'refund-status-notification' && finding.strength === 'informational'))
  assert.ok(!result.findings.some((finding) => finding.strength === 'weak' || finding.strength === 'strong'))
})

test('a request for a refund release fee is a contextual warning, not automatically high concern', () => {
  const result = analyzeMessage('Pay a processing fee to release your refund.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'refund-release-fee-request' && finding.strength === 'strong'))
  assert.ok(!result.findings.some((finding) => finding.highConcernTrigger))
})

test('an additional payment request to receive a refund is detected', () => {
  const result = analyzeMessage('Send an additional payment to receive your refund.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'refund-release-fee-request'))
})

test('an additional transfer request to receive a refund is detected', () => {
  const result = analyzeMessage('Make an additional transfer to receive your refund.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'refund-release-fee-request'))
})

test('an upfront fee to recover lost funds is detected as a payment recovery warning', () => {
  const result = analyzeMessage('Pay an upfront fee and we will recover your lost funds.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'refund-release-fee-request'))
})

test('an OTP request to reverse a transaction is high concern and explained', () => {
  const result = analyzeMessage('Share your OTP to reverse this transaction.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request' && finding.highConcernTrigger === 'direct-authentication'))
  assert.ok(!result.findings.some((finding) => finding.id === 'transaction-reversal-credential-request'))
  assert.match(result.findings.find((finding) => finding.id === 'credentials-request')?.explanation ?? '', /transaction or refund/i)
})

test('an OTP reversal request written in reverse order is detected', () => {
  const result = analyzeMessage('To cancel the payment, enter your verification code.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
  assert.ok(!result.findings.some((finding) => finding.id === 'transaction-reversal-credential-request'))
})

test('negated OTP advice about payment reversal remains non-alarming', () => {
  const result = analyzeMessage('Never share your OTP to reverse a transaction.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'credentials-request' || finding.id === 'transaction-reversal-credential-request'))
})

test('educational payment recovery examples remain suppressed', () => {
  const result = analyzeMessage('Scam awareness: fraudsters may ask you to pay an upfront fee to recover lost funds.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
})

test('quoted suspicious refund instructions keep the existing quotation behavior', () => {
  const educational = analyzeMessage('The suspicious text said: “Pay a fee to release your refund and share your OTP.”')
  const raw = analyzeMessage('“Pay a fee to release your refund and share your OTP.”')

  assert.equal(educational.riskLevel, 'no-obvious-warning-signs')
  assert.equal(educational.findings.length, 0)
  assert.equal(raw.riskLevel, 'high-concern')
  assert.ok(raw.findings.some((finding) => finding.id === 'refund-release-fee-request'))
  assert.ok(raw.findings.some((finding) => finding.id === 'credentials-request'))
})

test('reported scam instructions with a semicolon inside quotation marks remain quoted', () => {
  const result = analyzeMessage('The suspicious text said: “Pay a fee to release your refund; share your OTP.”')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
})

test('reported scam instructions with periods inside quotation marks remain quoted', () => {
  const result = analyzeMessage('The suspicious text said: “Pay a fee to release your refund. Share your OTP.”')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
})

test('reported scam instructions with other punctuation and line breaks remain quoted', () => {
  const result = analyzeMessage('The message reads: “Is a refund pending? Pay a fee;\nshare your OTP!”')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
})

test('an active OTP instruction after a reported quotation remains actionable', () => {
  const result = analyzeMessage('The text said: "Share your OTP." Please share your PIN now.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request' && /share your PIN/i.test(finding.evidence ?? '')))
})

test('periods inside reported quotations do not suppress a later active instruction', () => {
  const result = analyzeMessage('A suspicious message read: “Your account is blocked. Share your OTP.” Now provide your PIN to support.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request' && /provide your PIN/i.test(finding.evidence ?? '')))
})

test('educational plural scam examples remain suppressed without suppressing a later request', () => {
  const educational = analyzeMessage('Educational examples of refund scams: "Pay a fee; share OTP." Another scam example: "Transfer a deposit; send your PIN."')
  const active = analyzeMessage('Educational examples of refund scams: "Pay a fee; share OTP." Please share your PIN now.')

  assert.notEqual(educational.riskLevel, 'high-concern')
  assert.ok(!educational.findings.some((finding) => finding.highConcernTrigger === 'direct-authentication'))
  assert.equal(active.riskLevel, 'high-concern')
})

test('an unbalanced reported quotation does not suppress following active instructions', () => {
  const result = analyzeMessage('The text said: “Share your OTP. Please provide your PIN now.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
})

test('nested reported quotations stay educational while an outer active instruction is checked', () => {
  const result = analyzeMessage('The message said: “They wrote, ‘Share your OTP.’” Please share your PIN now.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request' && /share your PIN/i.test(finding.evidence ?? '')))
})

test('single-quoted raw suspicious instructions remain analyzable', () => {
  const result = analyzeMessage("'Share your OTP now.'")

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
})

test('passive and transaction-directed authentication requests are high concern', () => {
  const examples = [
    'Your refund requires an OTP.',
    'Your refund requires a password.',
    'Cancel this transaction with your OTP.',
    'Provide your net-banking credentials to support.',
    'Your account requires your PIN to restore access.',
    'Share your verification code to reverse the debit.',
  ]

  for (const example of examples) {
    const result = analyzeMessage(example)
    assert.equal(result.riskLevel, 'high-concern', example)
    assert.ok(result.findings.some((finding) => finding.id === 'credentials-request' && finding.highConcernTrigger === 'direct-authentication'), example)
  }
})

test('neutral authentication mentions without a request remain unflagged', () => {
  const result = analyzeMessage('An OTP is a one-time password used by some services.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'credentials-request'))
})

test('negated passive authentication requirements do not trigger high concern', () => {
  const result = analyzeMessage('Your refund does not require an OTP or password.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'credentials-request'))
})

test('transaction-related OTP and password phrases are not high concern without an active disclosure request', () => {
  const examples = [
    'Do not provide an OTP to cancel a debit.',
    'A scam warning: scammers may say OTP to reverse a debit; never share it.',
    'Avoid sharing your verification code to reverse a debit.',
    'Never share your OTP to reverse a transaction.',
    'Do not disclose your password to cancel a payment.',
    'The guide mentions OTP to cancel a debit but does not ask anyone to share a code.',
  ]

  for (const example of examples) {
    const result = analyzeMessage(example)
    assert.notEqual(result.riskLevel, 'high-concern', example)
    assert.ok(!result.findings.some((finding) => finding.id === 'credentials-request' && finding.highConcernTrigger === 'direct-authentication'), example)
  }
})

test('real transaction credential disclosure requests remain high concern', () => {
  const examples = [
    'Share your OTP to reverse this transaction.',
    'Provide your password to cancel the payment.',
    'Enter your verification code to cancel this debit.',
  ]

  for (const example of examples) {
    const result = analyzeMessage(example)
    const finding = result.findings.find((item) => item.id === 'credentials-request')
    assert.equal(result.riskLevel, 'high-concern', example)
    assert.equal(finding?.strength, 'strong', example)
    assert.equal(finding?.highConcernTrigger, 'direct-authentication', example)
    assert.ok(finding?.evidence, example)
  }
})

test('passive authentication requirements match consistently across whitespace', () => {
  const examples = [
    'Your refund requires an OTP.',
    'Your refund requires an\nOTP.',
    'Your refund requires an\r\nOTP.',
    'Your refund requires an    OTP.',
    'Your refund requires an\t OTP.',
    'Your refund requires a password.',
  ]

  for (const example of examples) {
    const result = analyzeMessage(example)
    const finding = result.findings.find((item) => item.id === 'credentials-request')
    assert.equal(result.riskLevel, 'high-concern', example)
    assert.equal(finding?.strength, 'strong', example)
    assert.equal(finding?.highConcernTrigger, 'direct-authentication', example)
    assert.ok(finding?.evidence, example)
  }
})

test('punctuation between a passive OTP requirement and the secret is accepted and preserved in evidence', () => {
  const input = 'Your refund requires an: OTP!'
  const result = analyzeMessage(input)
  const finding = result.findings.find((item) => item.id === 'credentials-request')

  assert.equal(result.riskLevel, 'high-concern')
  assert.equal(finding?.strength, 'strong')
  assert.equal(finding?.highConcernTrigger, 'direct-authentication')
  assert.equal(finding?.evidence, 'refund requires an: OTP')
})

test('authentication evidence preserves original newline formatting', () => {
  const input = 'Your refund requires an\nOTP.'
  const result = analyzeMessage(input)
  const finding = result.findings.find((item) => item.id === 'credentials-request')

  assert.equal(result.riskLevel, 'high-concern')
  assert.equal(finding?.evidence, 'refund requires an\nOTP')
})

test('authentication evidence preserves original CRLF formatting', () => {
  const input = 'Your refund requires an\r\nOTP.'
  const result = analyzeMessage(input)
  const finding = result.findings.find((item) => item.id === 'credentials-request')

  assert.equal(result.riskLevel, 'high-concern')
  assert.equal(finding?.evidence, 'refund requires an\r\nOTP')
})

test('negation followed by an active credential request remains high concern', () => {
  const result = analyzeMessage('Do not provide your OTP to anyone. Provide your OTP to support now.')
  const finding = result.findings.find((item) => item.id === 'credentials-request')

  assert.equal(result.riskLevel, 'high-concern')
  assert.equal(finding?.evidence, 'Provide your OTP')
})

test('an active request followed by an educational warning retains only the active evidence', () => {
  const result = analyzeMessage('Share your OTP now. Educational example: “Never share codes.”')
  const finding = result.findings.find((item) => item.id === 'credentials-request')

  assert.equal(result.riskLevel, 'high-concern')
  assert.match(finding?.evidence ?? '', /Share your OTP/i)
  assert.doesNotMatch(finding?.evidence ?? '', /Never share codes/i)
})

test('routine maintenance without pressure or sensitive requests is not flagged', () => {
  const examples = [
    'Online banking will be unavailable during scheduled maintenance tonight.',
    'Your account will be temporarily restricted during scheduled maintenance. Use our trusted banking app to update your contact details after service resumes.',
    'Scheduled bank maintenance is planned for Sunday. No action is required.',
  ]

  for (const example of examples) {
    const result = analyzeMessage(example)
    assert.equal(result.riskLevel, 'no-obvious-warning-signs', example)
    assert.ok(!result.findings.some((finding) => finding.highConcernTrigger), example)
  }
})

test('maintenance wording does not suppress OTP or password requests', () => {
  const examples = [
    'Scheduled maintenance will temporarily restrict your account. Use the trusted app and share your OTP to restore access.',
    'Scheduled maintenance will temporarily restrict your account. Use the trusted app and provide your password when service resumes.',
  ]

  for (const example of examples) {
    const result = analyzeMessage(example)
    assert.equal(result.riskLevel, 'high-concern', example)
    assert.ok(result.findings.some((finding) => finding.id === 'credentials-request' && finding.highConcernTrigger === 'direct-authentication'), example)
  }
})

test('an external link in a maintenance notice is not hidden by the routine-message exception', () => {
  const result = analyzeMessage('Scheduled maintenance will temporarily restrict your account. Update banking information at https://banking.example.net/restore.')

  assert.notEqual(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'account-access-threat'))
})

test('account security combination evidence includes alert and follow-up action', () => {
  const result = analyzeMessage('A suspicious login was detected on your account. Sign in to restore access at https://example.com/login.')
  const finding = result.findings.find((item) => item.id === 'account-security-link-combination')

  assert.ok(finding)
  assert.match(finding.evidence ?? '', /suspicious login/i)
  assert.match(finding.evidence ?? '', /https:\/\/example\.com\/login/i)
})

test('account compromise and linked recovery evidence includes destination', () => {
  const result = analyzeMessage('Your account was compromised. Sign in at https://example.com/login to restore access.')
  const finding = result.findings.find((item) => item.id === 'account-security-link-combination')

  assert.ok(finding)
  assert.match(finding.evidence ?? '', /account was compromised/i)
  assert.match(finding.evidence ?? '', /https:\/\/example\.com\/login/i)
})

test('scheduled maintenance context does not escalate to high concern', () => {
  const result = analyzeMessage('Your account may be temporarily restricted during scheduled maintenance. Update banking details in the trusted app after service resumes.')

  assert.notEqual(result.riskLevel, 'high-concern')
  assert.ok(!result.findings.some((finding) => finding.highConcernTrigger))
})

test('a raw OTP instruction inside outer quotation marks is still analyzed', () => {
  const result = analyzeMessage('“Share your OTP to release this refund.”')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
  assert.ok(!result.findings.some((finding) => finding.id === 'transaction-reversal-credential-request'))
})

test('an educational refund-scam example with internal punctuation stays non-alarming', () => {
  const result = analyzeMessage('Educational example of a refund scam: “Pay a release fee; share your OTP.”')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
})

test('a requested security deposit to recover funds is a warning, not high concern', () => {
  const result = analyzeMessage('Transfer a security deposit to recover your funds.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'refund-release-fee-request'))
  assert.ok(!result.findings.some((finding) => finding.highConcernTrigger))
})

test('a security deposit mention without a payment instruction is not flagged', () => {
  const result = analyzeMessage('Our recovery policy describes a security deposit that is returned after settlement.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'refund-release-fee-request'))
})

test('a clearance charge to release money is a warning', () => {
  const result = analyzeMessage('Your money is stuck. Pay a clearance charge to release it.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'refund-release-fee-request'))
})

test('a held parcel, re-delivery fee, short deadline, and HTTP link are explained together', () => {
  const input = `DELIVERY NOTICE

Your parcel is on hold because the delivery address could not be verified.

Pay a small re-delivery fee of Rs. 25 within 2 hours to avoid return.

Confirm your details and pay here:

http://parcel-tracking-check.com/update

Do not share this message with anyone.`
  const result = analyzeMessage(input)
  const fee = result.findings.find((finding) => finding.id === 'delivery-fee-request')
  const combination = result.findings.find((finding) => finding.id === 'delivery-hold-payment-combination')
  const urgency = result.findings.find((finding) => finding.id === 'contextual-urgency')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.equal(fee?.strength, 'weak')
  assert.match(fee?.evidence ?? '', /pay a small re-delivery fee of Rs\. 25/i)
  assert.equal(combination?.strength, 'weak')
  assert.match(combination?.evidence ?? '', /parcel is on hold/i)
  assert.match(combination?.evidence ?? '', /re-delivery fee/i)
  assert.equal(urgency?.strength, 'weak')
  assert.match(urgency?.evidence ?? '', /within 2 hours/i)
  assert.ok(result.findings.some((finding) => finding.id === 'message-link-1-unencrypted-connection' && finding.strength === 'informational'))
  assert.ok(!result.findings.some((finding) => finding.highConcernTrigger))
})

test('an explicit re-delivery fee request is detected without requiring an HTTP finding', () => {
  const result = analyzeMessage('Pay a small re-delivery fee of Rs. 25 to receive your parcel.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'delivery-fee-request' && finding.strength === 'weak'))
})

test('delivery payment urgency is contextual and ordinary urgency alone is not enough', () => {
  const delivery = analyzeMessage('Pay the delivery fee within 2 hours to receive your package.')
  const ordinary = analyzeMessage('The team needs an urgent response within 2 hours about tomorrow’s meeting.')

  assert.ok(delivery.findings.some((finding) => finding.id === 'delivery-fee-request'))
  assert.ok(delivery.findings.some((finding) => finding.id === 'contextual-urgency' && finding.strength === 'weak'))
  assert.ok(!ordinary.findings.some((finding) => finding.id === 'contextual-urgency'))
  assert.equal(ordinary.riskLevel, 'no-obvious-warning-signs')
})

test('legitimate delivery status and fee notifications are not treated as payment requests', () => {
  const examples = [
    'Your parcel is on hold because the address could not be verified. Update it in the carrier app; no payment is required.',
    'Your package is out for delivery today. The delivery fee was paid at checkout.',
    'A re-delivery fee may apply. Review the carrier’s published policy or contact customer service using its official website.',
  ]

  for (const example of examples) {
    const result = analyzeMessage(example)
    assert.ok(!result.findings.some((finding) => finding.id === 'delivery-fee-request'), example)
    assert.ok(!result.findings.some((finding) => finding.id === 'delivery-hold-payment-combination'), example)
    assert.notEqual(result.riskLevel, 'high-concern', example)
  }
})

test('parcel hold or return warnings alone do not create a delivery payment finding', () => {
  const result = analyzeMessage('Your parcel is on hold until the delivery address is verified. It may be returned to sender.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'delivery-fee-request' || finding.id === 'delivery-hold-payment-combination'))
})

test('ordinary recovery policy discussion is not treated as a payment request', () => {
  const result = analyzeMessage('Our recovery policy explains how funds are returned after a completed review.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'refund-release-fee-request'))
})

test('a refund blocked on payment verification is a warning, not a completed refund status', () => {
  const result = analyzeMessage('Your refund cannot be processed until you complete payment verification.')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'refund-payment-verification-request' && finding.strength === 'weak'))
  assert.ok(!result.findings.some((finding) => finding.id === 'refund-status-notification'))
  assert.ok(!result.findings.some((finding) => finding.highConcernTrigger))
})

test('refund pending is not reported as successfully processed', () => {
  const result = analyzeMessage('Your refund is pending and is being reviewed.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'refund-status-notification'))
})

test('refund verification that requests an OTP is high concern with transaction context', () => {
  const result = analyzeMessage('To release your refund, share your OTP to complete payment verification.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
  assert.ok(!result.findings.some((finding) => finding.id === 'transaction-reversal-credential-request'))
})

test('ordinary refund policy processing fees are not mistaken for a payment request', () => {
  const result = analyzeMessage('Our refund policy includes a processing fee for returned goods.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'refund-release-fee-request'))
})

test('an OTP request to reverse a debit gets transaction-specific context', () => {
  const result = analyzeMessage('Share your OTP to reverse this debit.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
  assert.ok(!result.findings.some((finding) => finding.id === 'transaction-reversal-credential-request'))
})

test('a password request to reverse a payment gets transaction-specific context', () => {
  const result = analyzeMessage('Enter your password to reverse the payment.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
  assert.ok(!result.findings.some((finding) => finding.id === 'transaction-reversal-credential-request'))
})

test('a verification code request to cancel an unauthorized debit gets transaction context', () => {
  const result = analyzeMessage('Share the verification code to cancel the unauthorized debit.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
  assert.ok(!result.findings.some((finding) => finding.id === 'transaction-reversal-credential-request'))
})

test('negated OTP refund and reversal instructions remain non-alarming', () => {
  const examples = [
    'Never share your OTP to release a refund.',
    'Do not enter your password to reverse a payment.',
    'Avoid sharing your verification code to cancel an unauthorized debit.',
  ]

  for (const example of examples) {
    const result = analyzeMessage(example)
    assert.equal(result.riskLevel, 'no-obvious-warning-signs', example)
    assert.ok(!result.findings.some((finding) => finding.id === 'credentials-request' || finding.id === 'transaction-reversal-credential-request'), example)
  }
})

test('unrelated transaction and banking sentences do not combine into high concern', () => {
  const result = analyzeMessage('Your payment failed yesterday. Separately, update banking information for payroll in the company app.')

  assert.notEqual(result.riskLevel, 'high-concern')
  assert.ok(!result.findings.some((finding) => finding.id === 'account-verification-combination' || finding.id === 'kyc-impersonation-combination'))
})

test('scheduled maintenance without an action request is not high concern', () => {
  const result = analyzeMessage('Online banking will be unavailable during scheduled maintenance tonight.')

  assert.notEqual(result.riskLevel, 'high-concern')
  assert.ok(!result.findings.some((finding) => finding.highConcernTrigger))
})

test('unrelated account-alert and banking-request sentences do not create high concern', () => {
  const result = analyzeMessage('An unfamiliar login was detected yesterday. Separately, update banking information for payroll in the company app.')

  assert.notEqual(result.riskLevel, 'high-concern')
  assert.ok(!result.findings.some((finding) => finding.id === 'account-security-link-combination'))
  assert.ok(!result.findings.some((finding) => finding.highConcernTrigger))
})

test('negated banking-identifier instructions remain suppressed', () => {
  const result = analyzeMessage('Do not submit your IFSC code or Aadhaar number in response to an unexpected message.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'banking-identifier-request' || finding.id === 'personal-information-request'))
})

test('quoted KYC scam instructions remain educational while raw suspicious wording is checked', () => {
  const education = analyzeMessage('Be careful of messages saying: “Your KYC will be suspended and submit your Aadhaar number.”')
  const raw = analyzeMessage('“Your KYC will be suspended unless you submit your Aadhaar number at https://example.com/kyc.”')

  assert.equal(education.riskLevel, 'no-obvious-warning-signs')
  assert.equal(education.findings.length, 0)
  assert.equal(raw.riskLevel, 'high-concern')
  assert.ok(raw.findings.some((finding) => finding.id === 'kyc-impersonation-combination'))
})

test('ordinary conversation with urgency and verification wording is not enough to trigger findings', () => {
  const result = analyzeMessage('I urgently need to verify the meeting time before we leave for dinner.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
})

test('quoted scam text is treated as an example, not an active request', () => {
  const result = analyzeMessage('The suspicious text said: “Send your OTP immediately or your account will be blocked.”')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
})

test('inline quoted scam wording in a discussion is not treated as an active request', () => {
  const result = analyzeMessage('The text "send your OTP immediately" looks suspicious.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
})

test('a raw suspicious message pasted inside quotation marks is still analyzed', () => {
  const result = analyzeMessage('"Your account is locked. Send your OTP immediately."')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
  assert.ok(result.findings.every((finding) => finding.evidence))
})

test('negated sensitive information request is not treated as an instruction', () => {
  const result = analyzeMessage('Do not provide your password or verification code to anyone.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(!result.findings.some((finding) => finding.id === 'credentials-request'))
})

test('a negation suppresses its instruction but not a later active OTP request', () => {
  const result = analyzeMessage('Never share your OTP with strangers, but send your OTP to this support agent now.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
  assert.match(result.findings.find((finding) => finding.id === 'credentials-request')?.evidence ?? '', /send your OTP/i)
})

test('a negation about links does not suppress a separate OTP request', () => {
  const result = analyzeMessage('Do not click suspicious links. Share your OTP with the support agent.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
})

test('a negated link instruction does not suppress an active request in the same sentence', () => {
  const result = analyzeMessage('Do not click the link, and send your OTP to this support agent.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
})

test('educational warnings about gift-card code requests remain non-alarming', () => {
  const result = analyzeMessage('Be careful of messages asking you to buy gift cards and send the codes.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
})

test('a direct OTP request remains high concern alongside weak findings', () => {
  const result = analyzeMessage('Your account may be locked. Send your OTP immediately.')

  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.findings.some((finding) => finding.id === 'account-access-threat'))
  assert.ok(result.findings.some((finding) => finding.id === 'credentials-request'))
})

test('ordinary message wording does not claim the content is safe', () => {
  const result = analyzeMessage('Your appointment is confirmed for Friday afternoon.')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.match(result.summary, /does not confirm.*safe/i)
})

test('empty message input is inconclusive', () => {
  assert.equal(analyzeMessage('  ').riskLevel, 'inconclusive')
})

test('malformed URL input is inconclusive', () => {
  assert.equal(analyzeUrl('not a url').riskLevel, 'inconclusive')
})

test('URL review explains embedded credentials', () => {
  const result = analyzeUrl('https://user:secret@example.com/login')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.equal(result.findings[0].id, 'embedded-credentials')
  assert.match(result.limitations[0], /does not visit the site/i)
})

test('HTTP-only URL is an informational observation and does not elevate risk', () => {
  const clean = analyzeUrl('https://example.com')
  const http = analyzeUrl('http://example.com')

  assert.equal(clean.riskLevel, 'no-obvious-warning-signs')
  assert.match(clean.summary, /does not verify.*safe/i)
  assert.equal(http.riskLevel, 'no-obvious-warning-signs')
  assert.equal(http.findings[0].id, 'unencrypted-connection')
  assert.equal(http.findings[0].strength, 'informational')
})

test('valid IPv4 and IPv6 literals are identified as weak observations', () => {
  const ipv4 = analyzeUrl('https://192.0.2.10/login')
  const ipv6 = analyzeUrl('https://[2001:db8::1]/login')

  assert.equal(ipv4.riskLevel, 'some-warning-signs')
  assert.equal(ipv4.findings.find((finding) => finding.id === 'ip-address-host')?.strength, 'weak')
  assert.equal(ipv6.riskLevel, 'some-warning-signs')
  assert.match(ipv6.findings.find((finding) => finding.id === 'ip-address-host')?.title ?? '', /IPv6/)
})

test('invalid IPv4 addresses are rejected instead of classified as IP hosts', () => {
  const result = analyzeUrl('https://256.1.1.1/login')

  assert.equal(result.riskLevel, 'inconclusive')
  assert.ok(!result.findings.some((finding) => finding.id === 'ip-address-host'))
})

test('ordinary HTTPS domain has no structural warning findings', () => {
  const result = analyzeUrl('https://www.example.com/account')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.equal(result.findings.length, 0)
})

test('domain-like subdomain explains the estimated registered destination', () => {
  const result = analyzeUrl('https://paypal.com.fake-example.org/login')
  const finding = result.findings.find((item) => item.id === 'domain-like-subdomain')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.match(finding?.explanation ?? '', /fake-example\.org/)
  assert.match(finding?.explanation ?? '', /does not prove.*malicious/i)
})

test('excessive subdomain depth is a weak finding, not proof of malicious intent', () => {
  const result = analyzeUrl('https://one.two.three.four.five.example.org/login')
  const finding = result.findings.find((item) => item.id === 'many-domain-levels')

  assert.equal(result.riskLevel, 'some-warning-signs')
  assert.equal(finding?.strength, 'weak')
})

test('explicit Punycode is weak while a normal internationalized hostname is informational', () => {
  const punycode = analyzeUrl('https://xn--bcher-kva.example/path')
  const international = analyzeUrl('https://bücher.example/path')

  assert.equal(punycode.riskLevel, 'some-warning-signs')
  assert.ok(punycode.findings.some((finding) => finding.id === 'punycode-host' && finding.strength === 'weak'))
  assert.equal(international.riskLevel, 'no-obvious-warning-signs')
  assert.ok(international.findings.some((finding) => finding.id === 'internationalized-host' && finding.strength === 'informational'))
})

test('ordinary encoded paths are informational and encoded separators are weak', () => {
  const ordinary = analyzeUrl('https://example.com/search?q=hello%20world')
  const suspicious = analyzeUrl('https://example.com/a%2Fb')

  assert.equal(ordinary.riskLevel, 'no-obvious-warning-signs')
  assert.ok(ordinary.findings.some((finding) => finding.id === 'encoded-url-path' && finding.strength === 'informational'))
  assert.equal(suspicious.riskLevel, 'some-warning-signs')
  assert.ok(suspicious.findings.some((finding) => finding.id === 'suspicious-url-encoding' && finding.strength === 'weak'))
})

test('percent-encoded host characters are reported when the browser parser accepts them', () => {
  const result = analyzeUrl('https://%62ank.example/login')

  assert.ok(['inconclusive', 'some-warning-signs'].includes(result.riskLevel))
  if (result.riskLevel !== 'inconclusive') {
    assert.ok(result.findings.some((finding) => finding.id === 'encoded-hostname' && finding.strength === 'strong'))
  }
})

test('embedded credentials are strong and combine with an independent warning for high concern', () => {
  const credentialsOnly = analyzeUrl('https://user:secret@example.com/login')
  const combined = analyzeUrl('https://user:secret@192.0.2.10/login')

  assert.equal(credentialsOnly.riskLevel, 'some-warning-signs')
  assert.equal(credentialsOnly.findings.find((finding) => finding.id === 'embedded-credentials')?.strength, 'strong')
  assert.equal(combined.riskLevel, 'high-concern')
  assert.ok(combined.findings.some((finding) => finding.id === 'ip-address-host'))
})

test('common URL shorteners are informational and are never expanded', () => {
  const result = analyzeUrl('https://bit.ly/abc123')

  assert.equal(result.riskLevel, 'no-obvious-warning-signs')
  assert.ok(result.findings.some((finding) => finding.id === 'shortened-url' && finding.strength === 'informational'))
})

test('malformed and unsupported scheme URLs are inconclusive', () => {
  assert.equal(analyzeUrl('https://[not-ipv6]/path').riskLevel, 'inconclusive')
  assert.equal(analyzeUrl('javascript:alert(1)').riskLevel, 'inconclusive')
})

test('insufficient screenshot OCR text returns inconclusive', () => {
  assert.equal(analyzeExtractedScreenshotText('Hi, click.').riskLevel, 'inconclusive')
  assert.equal(analyzeExtractedScreenshotText('   ').riskLevel, 'inconclusive')
  assert.equal(analyzeExtractedScreenshotText('').riskLevel, 'inconclusive')
})

test('readable screenshot OCR text uses message checks and adds OCR limitations', () => {
  const result = analyzeExtractedScreenshotText('Please send your one-time code immediately to restore access to your account.')

  assert.equal(result.inputMode, 'screenshot')
  assert.equal(result.riskLevel, 'high-concern')
  assert.ok(result.limitations.some((limitation) => /English OCR/.test(limitation)))
  assert.ok(result.limitations.some((limitation) => /not a scam-risk score/i.test(limitation)))
})

test('low-confidence and garbled OCR extraction are inconclusive', () => {
  const readableText = 'Please send your one-time code immediately to restore access to your account.'

  assert.equal(analyzeExtractedScreenshotText(readableText, 20).riskLevel, 'inconclusive')
  assert.equal(analyzeExtractedScreenshotText('@@@ ### %%% !!! &&& *** ??? ###', 90).riskLevel, 'inconclusive')
})

test('screenshot OCR receives the in-memory file, reports progress, and terminates its worker', async () => {
  const image = new File(['image bytes'], 'message.png', { type: 'image/png' })
  const progress = []
  let receivedImage
  let terminated = false
  const result = await analyzeScreenshot(image, (value) => progress.push(value), { imageInspector: readableImageInspector, workerFactory: async (logger) => {
    logger({ status: 'recognizing text', progress: 1.4 })
    return {
      recognize: async (input) => {
        receivedImage = input
        return { data: { text: 'Please send your one-time code immediately to restore access to your account.', confidence: 92 } }
      },
      terminate: async () => { terminated = true },
    }
  } })

  assert.equal(receivedImage, image)
  assert.equal(result.riskLevel, 'high-concern')
  assert.deepEqual(progress, [{ stage: 'recognizing', progress: 1 }])
  assert.equal(terminated, true)
  assert.ok(!Object.values(result).includes(image))
})

test('unreadable screenshot OCR returns inconclusive and releases its worker', async () => {
  const image = new File(['image bytes'], 'blank.png', { type: 'image/png' })
  let terminated = false
  const result = await analyzeScreenshot(image, () => {}, { imageInspector: readableImageInspector, workerFactory: async () => ({
    recognize: async () => ({ data: { text: '   ' } }),
    terminate: async () => { terminated = true },
  }) })

  assert.equal(result.riskLevel, 'inconclusive')
  assert.equal(terminated, true)
})

test('OCR setup failure returns inconclusive instead of fabricated results', async () => {
  const image = new File(['image bytes'], 'message.png', { type: 'image/png' })
  const result = await analyzeScreenshot(image, () => {}, { imageInspector: readableImageInspector, workerFactory: async () => {
    throw new Error('OCR resources unavailable')
  } })

  assert.equal(result.riskLevel, 'inconclusive')
  assert.match(result.summary, /could not be read/i)
})

test('OCR recognition errors terminate the worker and return inconclusive', async () => {
  const image = new File(['image bytes'], 'message.png', { type: 'image/png' })
  let terminated = false
  const result = await analyzeScreenshot(image, () => {}, { imageInspector: readableImageInspector, workerFactory: async () => ({
    recognize: async () => { throw new Error('Recognition failed') },
    terminate: async () => { terminated = true },
  }) })

  assert.equal(result.riskLevel, 'inconclusive')
  assert.equal(terminated, true)
})

test('unsupported and oversized image files are rejected before OCR starts', async () => {
  let workerStarted = false
  const workerFactory = async () => {
    workerStarted = true
    throw new Error('Should not be called')
  }
  const wrongType = new File(['text'], 'note.txt', { type: 'text/plain' })
  const tooLarge = new File([new Uint8Array(10 * 1024 * 1024 + 1)], 'large.png', { type: 'image/png' })

  assert.equal((await analyzeScreenshot(wrongType, () => {}, { imageInspector: readableImageInspector, workerFactory })).riskLevel, 'inconclusive')
  assert.equal((await analyzeScreenshot(tooLarge, () => {}, { imageInspector: readableImageInspector, workerFactory })).riskLevel, 'inconclusive')
  assert.equal(workerStarted, false)
})

test('small, huge, and corrupted images are rejected before worker initialization', async () => {
  const image = new File(['image bytes'], 'message.png', { type: 'image/png' })
  let workerStarted = false
  const workerFactory = async () => {
    workerStarted = true
    throw new Error('Should not initialize')
  }
  const tooSmall = await analyzeScreenshot(image, () => {}, {
    imageInspector: async () => ({ width: 239, height: 600 }), workerFactory,
  })
  const tooLargeInPixels = await analyzeScreenshot(image, () => {}, {
    imageInspector: async () => ({ width: 6000, height: 5000 }), workerFactory,
  })
  const corrupted = await analyzeScreenshot(image, () => {}, {
    imageInspector: async () => { throw new Error('Invalid image data') }, workerFactory,
  })

  assert.equal(tooSmall.riskLevel, 'inconclusive')
  assert.equal(tooLargeInPixels.riskLevel, 'inconclusive')
  assert.equal(corrupted.riskLevel, 'inconclusive')
  assert.equal(workerStarted, false)
})

test('image dimension boundaries are accepted and rejected consistently', async () => {
  const image = new File(['image bytes'], 'message.png', { type: 'image/png' })
  let workerTerminated = false
  const workerFactory = async () => ({
    recognize: async () => ({ data: { text: 'This is ordinary readable screenshot content for our test.', confidence: 80 } }),
    terminate: async () => { workerTerminated = true },
  })
  const boundary = await analyzeScreenshot(image, () => {}, {
    imageInspector: async () => ({ width: 240, height: 120 }), workerFactory,
  })
  const onePixelBelow = await analyzeScreenshot(image, () => {}, {
    imageInspector: async () => ({ width: 240, height: 119 }), workerFactory,
  })

  assert.equal(boundary.riskLevel, 'no-obvious-warning-signs')
  assert.equal(onePixelBelow.riskLevel, 'inconclusive')
  assert.equal(workerTerminated, true)
})

test('cancelled screenshot analysis terminates its worker', async () => {
  const image = new File(['image bytes'], 'message.png', { type: 'image/png' })
  const controller = new AbortController()
  let terminated = false
  const pendingRecognition = new Promise(() => {})
  const resultPromise = analyzeScreenshot(image, () => {}, {
    signal: controller.signal,
    imageInspector: readableImageInspector,
    workerFactory: async () => ({
      recognize: async () => pendingRecognition,
      terminate: async () => {
        terminated = true
      },
    }),
  })

  await new Promise((resolve) => setImmediate(resolve))
  controller.abort()
  const result = await resultPromise

  assert.equal(result.riskLevel, 'inconclusive')
  assert.match(result.summary, /stopped/i)
  assert.equal(terminated, true)
})

test('cancellation during worker initialization terminates the worker when it becomes available', async () => {
  const image = new File(['image bytes'], 'message.png', { type: 'image/png' })
  const controller = new AbortController()
  let resolveWorker
  let terminated = false
  const resultPromise = analyzeScreenshot(image, () => {}, {
    signal: controller.signal,
    imageInspector: readableImageInspector,
    workerFactory: () => new Promise((resolve) => { resolveWorker = resolve }),
  })

  await new Promise((resolve) => setImmediate(resolve))
  controller.abort()
  const result = await resultPromise
  resolveWorker({ recognize: async () => ({ data: { text: '' } }), terminate: async () => { terminated = true } })
  await new Promise((resolve) => setImmediate(resolve))

  assert.equal(result.riskLevel, 'inconclusive')
  assert.match(result.summary, /stopped/i)
  assert.equal(terminated, true)
})
