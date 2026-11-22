import type { AnalysisResult, Finding } from './types.ts'
import { classifyRisk, createInconclusiveResult } from './results.ts'

const urlLimitations = [
  'This review only checks the address structure. It does not visit the site, check a live reputation database, or confirm who owns the domain.',
  'The registered destination is estimated from hostname labels and common suffixes; this is not a complete public suffix or brand database.',
  'No obvious warning signs does not mean a website is safe. Avoid entering private details until you have independently verified the site.',
]

const shortenerHosts = new Set(['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'ow.ly', 'buff.ly', 'rebrand.ly', 'shorturl.at'])
const commonSecondLevelSuffixes = new Set([
  'ac.uk', 'co.uk', 'gov.uk', 'org.uk', 'com.au', 'net.au', 'org.au', 'co.in', 'firm.in',
  'net.in', 'org.in', 'com.br', 'com.cn', 'com.hk', 'co.jp', 'co.nz', 'co.za',
])
const familiarDomainEndings = 'com|net|org|co|io|gov|edu|bank'

function makeUrlResult(findings: Finding[]): AnalysisResult {
  const riskLevel = classifyRisk(findings)
  const messages = {
    inconclusive: {
      title: 'Inconclusive',
      summary: 'There was not enough usable information to complete this review.',
      recommendations: ['Try again with a complete address.', 'Verify unexpected requests through a trusted channel.'],
    },
    'high-concern': {
      title: 'High concern',
      summary: 'This address combines embedded login information with another structural warning sign.',
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

  return { inputMode: 'url', riskLevel, ...messages[riskLevel], findings, limitations: urlLimitations }
}

function getRawHostname(value: string): string {
  const withoutScheme = value.replace(/^[a-z][a-z\d+.-]*:\/\//i, '').replace(/^\/\//, '')
  const authority = withoutScheme.split(/[/?#]/, 1)[0] ?? ''
  const hostAndPort = authority.slice(authority.lastIndexOf('@') + 1)

  if (hostAndPort.startsWith('[')) return hostAndPort.slice(0, hostAndPort.indexOf(']') + 1)
  return hostAndPort.replace(/:\d*$/, '')
}

function isValidIpv4(host: string): boolean {
  const parts = host.split('.')
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}

function isIpv6(host: string): boolean {
  return host.startsWith('[') && host.endsWith(']')
}

function getRegisteredDomain(host: string): string {
  if (isIpv6(host) || isValidIpv4(host)) return host
  const labels = host.split('.').filter(Boolean)
  if (labels.length < 2) return host
  const lastTwo = labels.slice(-2).join('.')
  const labelCount = commonSecondLevelSuffixes.has(lastTwo) ? 3 : 2
  return labels.slice(-labelCount).join('.')
}

function addFinding(findings: Finding[], finding: Finding) {
  findings.push(finding)
}

export function analyzeUrl(input: string): AnalysisResult {
  const value = input.trim()
  if (!value || /\s/.test(value) || value.length > 2048) {
    return createInconclusiveResult('url', 'Enter one complete web address without spaces. The review does not open the address.')
  }

  // Accept only explicit HTTP(S) schemes; otherwise treat the input as a hostname or URL with an implicit HTTPS scheme.
  if (/^[a-z][a-z\d+.-]*:/i.test(value) && !/^https?:\/\//i.test(value)) {
    return createInconclusiveResult('url', 'Enter an http or https web address to review.')
  }

  let parsed: URL
  try {
    parsed = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`)
  } catch {
    return createInconclusiveResult('url', 'This does not look like a complete web address. Check it and try again.')
  }

  if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) {
    return createInconclusiveResult('url', 'Enter an http or https web address to review.')
  }

  const findings: Finding[] = []
  const host = parsed.hostname.toLowerCase()
  const rawHost = getRawHostname(value).toLowerCase()
  const registeredDomain = getRegisteredDomain(host)
  const labels = host.split('.').filter(Boolean)
  const registeredLabelCount = registeredDomain.split('.').length
  const subdomain = labels.slice(0, Math.max(0, labels.length - registeredLabelCount)).join('.')

  if (parsed.username || parsed.password) {
    addFinding(findings, {
      id: 'embedded-credentials',
      title: 'The address contains a user name or password',
      explanation: 'Login details embedded in a link can hide the true destination or expose credentials.',
      strength: 'strong',
      evidence: `${parsed.username ? 'username' : ''}${parsed.username && parsed.password ? ' and ' : ''}${parsed.password ? 'password' : ''} before ${host}`,
    })
  }

  if (isValidIpv4(host) || isIpv6(host)) {
    addFinding(findings, {
      id: 'ip-address-host',
      title: isIpv6(host) ? 'The link uses an IPv6 address instead of a domain name' : 'The link uses an IPv4 address instead of a domain name',
      explanation: 'A numeric destination can be harder to associate with an organisation. This does not by itself establish that the address is harmful.',
      strength: 'weak',
      evidence: host,
    })
  }

  const rawLabels = rawHost.split('.')
  if (rawLabels.some((label) => label.startsWith('xn--'))) {
    addFinding(findings, {
      id: 'punycode-host',
      title: 'The host contains a Punycode label',
      explanation: 'Punycode represents international characters in domain names. It can be legitimate, but similar-looking characters may make a destination harder to recognise.',
      strength: 'weak',
      evidence: host,
    })
  } else if ([...rawHost].some((character) => (character.codePointAt(0) ?? 0) > 0x7f)) {
    addFinding(findings, {
      id: 'internationalized-host',
      title: 'The host uses international characters',
      explanation: 'Internationalized domain names are common and can be legitimate. Check the displayed domain carefully because some characters can look alike.',
      strength: 'informational',
      evidence: host,
    })
  }

  if (rawHost.includes('%')) {
    addFinding(findings, {
      id: 'encoded-hostname',
      title: 'The host includes percent-encoded characters',
      explanation: 'Encoded hostname characters can make the destination harder to read. The browser’s parsed host is shown here for inspection.',
      strength: 'strong',
      evidence: `${rawHost} parses as ${host}`,
    })
  }

  if (labels.length > 5) {
    addFinding(findings, {
      id: 'many-domain-levels',
      title: 'The address has many domain levels',
      explanation: `A long chain of subdomains can make the destination harder to spot. The estimated registered destination is ${registeredDomain}; long subdomains can also be legitimate.`,
      strength: 'weak',
      evidence: host,
    })
  }

  const misleadingDomainPattern = new RegExp(`(?:^|\\.)[a-z0-9-]+\\.(?:${familiarDomainEndings})(?:\\.|$)`, 'i')
  if (subdomain && misleadingDomainPattern.test(subdomain)) {
    addFinding(findings, {
      id: 'domain-like-subdomain',
      title: 'A subdomain resembles a separate familiar domain',
      explanation: `The familiar-looking text appears before the actual estimated registered destination, ${registeredDomain}. This structure can be misleading, but does not prove the destination is malicious.`,
      strength: 'weak',
      evidence: `${subdomain} → ${registeredDomain}`,
    })
  }

  if (shortenerHosts.has(host)) {
    addFinding(findings, {
      id: 'shortened-url',
      title: 'The address uses a URL-shortening service',
      explanation: 'Shortened links hide their final destination until opened. This review does not expand the link or contact the service.',
      strength: 'informational',
      evidence: host,
    })
  }

  const encodedPath = /%[\da-f]{2}/i.test(`${parsed.pathname}${parsed.search}${parsed.hash}`)
  const suspiciousEncoding = /%(?:2e|2f|5c|40|25|0[0-9a-f]|1[0-9a-f])/i.test(`${parsed.pathname}${parsed.search}${parsed.hash}`)
  if (suspiciousEncoding) {
    addFinding(findings, {
      id: 'suspicious-url-encoding',
      title: 'The address encodes characters that can obscure its structure',
      explanation: 'Encoded separators or nested encoding can make a URL harder to inspect. Encoding is also used legitimately, so this is a structural warning only.',
      strength: 'weak',
      evidence: `${parsed.pathname}${parsed.search}${parsed.hash}`.slice(0, 180),
    })
  } else if (encodedPath) {
    addFinding(findings, {
      id: 'encoded-url-path',
      title: 'The address contains encoded path or query characters',
      explanation: 'Percent-encoding is a normal part of many URLs. It is shown as an observation and does not by itself indicate a problem.',
      strength: 'informational',
      evidence: `${parsed.pathname}${parsed.search}${parsed.hash}`.slice(0, 180),
    })
  }

  if (parsed.protocol === 'http:') {
    addFinding(findings, {
      id: 'unencrypted-connection',
      title: 'The address does not use an encrypted HTTPS connection',
      explanation: 'Information sent over HTTP may be exposed in transit. HTTPS alone does not prove a site is legitimate.',
      strength: 'informational',
      evidence: parsed.origin,
    })
  }

  const hasIndependentWarning = findings.some((finding) => finding.strength === 'weak')
  if (findings.some((finding) => finding.id === 'embedded-credentials') && hasIndependentWarning) {
    const credentials = findings.find((finding) => finding.id === 'embedded-credentials')
    if (credentials) credentials.highConcernTrigger = 'contextual-combination'
  }

  return makeUrlResult(findings)
}
