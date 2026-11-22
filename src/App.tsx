import './App.css'

const experiences = [
  {
    id: 'scam-check',
    number: '01',
    name: 'Scam Check',
    title: 'A second look before you act.',
    description:
      'Bring a suspicious message or link into focus. Learn what to question before you respond.',
    action: 'Scam Check is coming soon',
    className: 'experience-check',
    mark: '↗',
  },
  {
    id: 'scam-arena',
    number: '02',
    name: 'Scam Arena',
    title: 'Practise spotting the signs.',
    description:
      'Explore realistic situations and build confidence recognising the patterns scammers use.',
    action: 'Scam Arena is coming soon',
    className: 'experience-arena',
    mark: '◎',
  },
  {
    id: 'family-shield',
    number: '03',
    name: 'Family Shield',
    title: 'Make safer habits a shared thing.',
    description:
      'Find practical ways to talk about digital safety and help the people close to you stay alert.',
    action: 'Family Shield is coming soon',
    className: 'experience-family',
    mark: '⌂',
  },
]

function Brand() {
  return (
    <a className="brand" href="#home" aria-label="FORWARD? home">
      <span className="brand-mark" aria-hidden="true">F</span>
      <span>FORWARD<span className="brand-question">?</span></span>
    </a>
  )
}

function Arrow() {
  return <span className="arrow" aria-hidden="true">↗</span>
}

function Navigation() {
  return (
    <header className="site-header">
      <div className="header-inner">
        <Brand />
        <nav className="desktop-nav" aria-label="Main navigation">
          <a href="#home" aria-current="page">Home</a>
          <a href="#scam-check">Scam Check</a>
          <a href="#scam-arena">Scam Arena</a>
          <a href="#family-shield">Family Shield</a>
          <a href="#about">About</a>
        </nav>
        <a className="button button-small button-lime header-cta" href="#scam-check">
          Check a scam <Arrow />
        </a>
        <details className="mobile-menu">
          <summary aria-label="Toggle navigation"><span></span><span></span></summary>
          <nav aria-label="Mobile navigation" onClick={(event) => {
            event.currentTarget.closest('details')?.removeAttribute('open')
          }}>
            <a href="#home">Home</a>
            <a href="#scam-check">Scam Check</a>
            <a href="#scam-arena">Scam Arena</a>
            <a href="#family-shield">Family Shield</a>
            <a href="#about">About</a>
            <a href="#scam-check">Check a scam <Arrow /></a>
          </nav>
        </details>
      </div>
    </header>
  )
}

function ThreatDisplay() {
  return (
    <div className="threat-display" role="group" aria-label="Illustrative suspicious message example, not a live scan">
      <div className="display-topline"><span>ILLUSTRATIVE EXAMPLE / NOT A LIVE SCAN</span></div>
      <div className="message-card">
        <div className="sender-row"><span className="sender-avatar">B</span><div><strong>Bank support</strong><span>no-reply@secure-bank-alert.co</span></div><span className="sender-time">NOW</span></div>
        <p>Your account has been temporarily<br className="desktop-break" /> restricted. Verify your details now.</p>
        <div className="message-link"><span>secure-bank-alert.co/verify</span><Arrow /></div>
        <div className="scan-line" aria-hidden="true" />
      </div>
      <div className="signal-note"><span className="signal-dot" /> <span><strong>Example warning sign</strong><small>Sender and link don’t match</small></span><span className="note-index">DEMO</span></div>
      <div className="display-footer"><span>READ THE SIGNALS</span><span>DON’T RUSH THE REPLY</span></div>
      <span className="display-cross cross-one" aria-hidden="true">+</span>
      <span className="display-cross cross-two" aria-hidden="true">+</span>
    </div>
  )
}

function Hero() {
  return (
    <section className="hero section-wrap" id="home" aria-labelledby="hero-title">
      <div className="hero-copy">
        <p className="eyebrow"><span className="eyebrow-line" /> DIGITAL SAFETY, MADE HUMAN</p>
        <h1 id="hero-title">Think before<br />you <span>click.</span></h1>
        <p className="hero-description">One suspicious message can change everything. Recognise the warning signs, understand the risks and take control of your digital safety.</p>
        <div className="hero-actions">
          <a className="button button-lime" href="#scam-check">Check a suspicious message <Arrow /></a>
          <a className="text-link" href="#scam-arena">Explore Scam Arena <span aria-hidden="true">↓</span></a>
        </div>
        <div className="hero-footnote"><span className="footnote-mark">?</span> A calmer way to navigate a noisier internet.</div>
      </div>
      <ThreatDisplay />
      <div className="hero-index" aria-hidden="true"><span>01</span><i /> 04</div>
    </section>
  )
}

function ProblemSection() {
  return (
    <section className="problem-section" aria-labelledby="problem-title">
      <div className="section-wrap problem-inner">
        <div className="problem-heading"><p className="eyebrow eyebrow-dark">THE EVERYDAY REALITY</p><h2 id="problem-title">Scams don’t always<br />look like <em>scams.</em></h2></div>
        <p className="problem-intro">They arrive in familiar places, dressed up as ordinary moments. A pause to check can make all the difference.</p>
        <div className="signal-list">
          <article className="signal-item"><span className="signal-symbol symbol-message" aria-hidden="true">···</span><div><h3>Suspicious messages</h3><p>Unexpected urgency, requests, or promises that ask you to act fast.</p></div><span className="signal-arrow" aria-hidden="true">↗</span></article>
          <article className="signal-item"><span className="signal-symbol symbol-link" aria-hidden="true">⌁</span><div><h3>Fraudulent links</h3><p>Web addresses that look familiar at a glance but lead somewhere else.</p></div><span className="signal-arrow" aria-hidden="true">↗</span></article>
          <article className="signal-item"><span className="signal-symbol symbol-person" aria-hidden="true">◉</span><div><h3>Impersonation attempts</h3><p>Someone posing as a person or organisation you already trust.</p></div><span className="signal-arrow" aria-hidden="true">↗</span></article>
        </div>
      </div>
    </section>
  )
}

function Experiences() {
  return (
    <section className="experiences-section section-wrap" id="experiences" aria-labelledby="experiences-title">
      <div className="section-heading"><div><p className="eyebrow"><span className="eyebrow-line" /> YOUR NEXT MOVE</p><h2 id="experiences-title">Build your <span>digital instinct.</span></h2></div><p>Three ways to feel more prepared for whatever lands in your inbox.</p></div>
      <div className="experience-grid">
        {experiences.map((experience) => (
          <article className={`experience-card ${experience.className}`} id={experience.id} key={experience.id}>
            <div className="card-topline"><span>{experience.number} / EXPERIENCE</span><span className="card-mark" aria-hidden="true">{experience.mark}</span></div>
            <div className="card-art" aria-hidden="true"><span className="art-ring ring-one" /><span className="art-ring ring-two" /><span className="art-core">{experience.mark}</span><span className="art-label">{experience.name.toUpperCase()}</span></div>
            <div className="card-copy"><p className="card-kicker">{experience.name}</p><h3>{experience.title}</h3><p>{experience.description}</p></div>
            <a className="card-link" href="#coming-soon">{experience.action} <Arrow /></a>
          </article>
        ))}
      </div>
      <p className="coming-note" id="coming-soon"><span className="coming-dot" /> These experiences are in development. More soon.</p>
    </section>
  )
}

function HowItWorks() {
  const steps = [
    ['Notice', 'Something feels off. Trust that pause.'],
    ['Understand', 'Look for the details that don’t add up.'],
    ['Choose', 'Make your next move with more confidence.'],
  ]
  return (
    <section className="how-section" id="about" aria-labelledby="how-title">
      <div className="section-wrap how-inner">
        <div className="how-heading"><p className="eyebrow eyebrow-dark">A MOMENT OF CLARITY</p><h2 id="how-title">Pause. Read.<br /><span>Move forward.</span></h2><p>Digital safety doesn’t have to feel overwhelming. Start with one small moment of attention.</p></div>
        <div className="steps-list">{steps.map(([title, description], index) => <article className="step" key={title}><span className="step-number">0{index + 1}</span><div><h3>{title}</h3><p>{description}</p></div><span className="step-arrow" aria-hidden="true">↗</span></article>)}</div>
      </div>
    </section>
  )
}

function FinalCallout() {
  return <section className="final-section section-wrap" aria-labelledby="final-title"><div className="final-copy"><p className="eyebrow"><span className="eyebrow-line" /> A BETTER WAY FORWARD</p><h2 id="final-title">Your next click should be<br /><span>a smarter one.</span></h2></div><a className="button button-lime" href="#scam-check">Start with Scam Check <Arrow /></a><span className="final-orbit orbit-a" aria-hidden="true" /><span className="final-orbit orbit-b" aria-hidden="true" /></section>
}

function Footer() {
  return <footer className="site-footer"><div className="section-wrap footer-main"><div className="footer-brand"><Brand /><p>Helping people feel more confident<br />in a connected world.</p></div><div className="footer-nav"><span>EXPLORE</span><a href="#home">Home</a><a href="#scam-check">Scam Check</a><a href="#scam-arena">Scam Arena</a><a href="#family-shield">Family Shield</a><a href="#about">About</a></div><a className="back-top" href="#home">Back to top ↑</a></div><div className="section-wrap footer-bottom"><span>© 2026 FORWARD? All rights reserved.</span><span>Stay curious. Stay safe.</span></div></footer>
}

function App() {
  return <><a className="skip-link" href="#main-content">Skip to content</a><Navigation /><main id="main-content"><Hero /><ProblemSection /><Experiences /><HowItWorks /><FinalCallout /></main><Footer /></>
}

export default App
