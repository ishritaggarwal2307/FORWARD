import type { AnalysisResult, Finding } from './types.ts'
import { createInconclusiveResult } from './results.ts'

const urlLimitations = [
  'This review only checks the address structure. It does not visit the site, check a live reputation database, or confirm who owns the domain.',
  'No obvious warning signs does not mean a website is safe. Avoid entering private details until you have independently verified the site.',
]

function makeUrlResult(findings: Finding[]): AnalysisResult {
  const hasHighConcern = findings.some((finding) => finding.severity === 'high')
  const riskLevel = hasHighConcern
    ? 'high-concern'
    : findings.length > 0
      ? 'some-warning-signs'
      : 'no-obvious-warning-signs'

  const messages = {
    'high-concern': {
      title: 'High concern',
      summary: 'This address contains information that should not normally be part of a link.',
      recommendations: [
        'Do not open this address or enter information on it.',
        'If it claims to be from an organisation, visit that organisation using a saved bookmark or a known address.',
      ],
    },
    'some-warning-signs': {
      title: 'Some warning signs',
      summary: 'The address has a pattern that can make a destination harder to verify.',
      recommendations: [
        'Do not open the link from the message. Check the destination independently.',
        'Pay close attention to the exact host name, including everything before the first slash.',
      ],
    },
    'no-obvious-warning-signs': {
      title: 'No obvious warning signs detected',
      summary: 'These address checks did not find the patterns they look for. This does not verify the site or prove it is safe.',
      recommendations: [
        'Compare the domain with the organisation’s known official address.',
        'Do not rely on a familiar logo or HTTPS alone to decide whether a page is genuine.',
      ],
    },
  } as const

  return {
    inputMode: 'url',
    riskLevel,
    ...messages[riskLevel],
    findings,
    limitations: urlLimitations,
  }
}

export function analyzeUrl(input: string): AnalysisResult {
  const value = input.trim()
  if (!value || /\s/.test(value) || value.length > 2048) {
    return createInconclusiveResult('url', 'Enter one complete web address without spaces. The review does not open the address.')
  }

  let parsed: URL
  try {
    parsed = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : `https://${value}`)
  } catch {
    return createInconclusiveResult('url', 'This does not look like a complete web address. Check it and try again.')
  }

  if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) {
    return createInconclusiveResult('url', 'Enter an http or https web address to review.')
  }

  const findings: Finding[] = []
  const host = parsed.hostname.toLowerCase()

  if (parsed.username || parsed.password) {
    findings.push({
      id: 'embedded-credentials',
      title: 'The address contains a user name or password',
      explanation: 'Login details embedded in a link can hide the true destination or expose credentials.',
      severity: 'high',
      evidence: `${parsed.username ? 'username' : ''}${parsed.username && parsed.password ? ' and ' : ''}${parsed.password ? 'password' : ''} before ${host}`,
    })
  }

  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    findings.push({
      id: 'ip-address-host',
      title: 'The link uses a numeric IP address instead of a domain name',
      explanation: 'A numeric destination can be harder to associate with an organisation. It is unusual for many consumer account messages.',
      severity: 'moderate',
      evidence: host,
    })
  }

  if (host.includes('xn--')) {
    findings.push({
      id: 'encoded-domain',
      title: 'The domain uses encoded characters',
      explanation: 'Some international domain characters are represented in an encoded form that can resemble other letters. Check the exact domain carefully.',
      severity: 'moderate',
      evidence: host,
    })
  }

  if (host.split('.').filter(Boolean).length > 5) {
    findings.push({
      id: 'many-domain-levels',
      title: 'The address has many domain levels',
      explanation: 'A long chain of subdomains can make the registered domain harder to spot. Some legitimate sites also use long domains.',
      severity: 'moderate',
      evidence: host,
    })
  }

  if (parsed.protocol === 'http:') {
    findings.push({
      id: 'unencrypted-connection',
      title: 'The address does not use an encrypted HTTPS connection',
      explanation: 'Information sent over HTTP may be exposed in transit. HTTPS alone does not prove a site is legitimate.',
      severity: 'informational',
      evidence: parsed.origin,
    })
  }

  return makeUrlResult(findings)
}
