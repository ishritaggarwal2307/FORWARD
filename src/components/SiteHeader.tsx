import { Link, useLocation } from 'react-router-dom'

function Brand() {
  return (
    <Link className="brand" to="/" aria-label="FORWARD? home">
      <span className="brand-mark" aria-hidden="true">F</span>
      <span>FORWARD<span className="brand-question">?</span></span>
    </Link>
  )
}

function Arrow() {
  return <span className="arrow" aria-hidden="true">↗</span>
}

export function SiteHeader() {
  const { pathname } = useLocation()
  const links = [
    { label: 'Home', to: '/', current: pathname === '/' },
    { label: 'Scam Check', to: '/scam-check', current: pathname === '/scam-check' },
    { label: 'Scam Arena', to: '/scam-arena', current: pathname === '/scam-arena' },
    { label: 'Family Shield', to: '/family-shield', current: pathname === '/family-shield' },
    { label: 'About', to: '/#about', current: false },
  ]

  return (
    <header className="site-header">
      <div className="header-inner">
        <Brand />
        <nav className="desktop-nav" aria-label="Main navigation">
          {links.map((link) => (
            <Link key={link.label} to={link.to} aria-current={link.current ? 'page' : undefined}>
              {link.label}
            </Link>
          ))}
        </nav>
        <Link className="button button-small button-lime header-cta" to="/scam-check">
          Check a scam <Arrow />
        </Link>
        <details className="mobile-menu">
          <summary aria-label="Toggle navigation"><span></span><span></span></summary>
          <nav aria-label="Mobile navigation" onClick={(event) => {
            event.currentTarget.closest('details')?.removeAttribute('open')
          }}>
            {links.map((link) => <Link key={link.label} to={link.to}>{link.label}</Link>)}
            <Link to="/scam-check">Check a scam <Arrow /></Link>
          </nav>
        </details>
      </div>
    </header>
  )
}

export function SiteFooter() {
  return (
    <footer className="site-footer">
      <div className="section-wrap footer-main">
        <div className="footer-brand"><Brand /><p>Helping people feel more confident<br />in a connected world.</p></div>
        <nav className="footer-nav" aria-label="Footer navigation">
          <span>EXPLORE</span>
          <Link to="/">Home</Link>
          <Link to="/scam-check">Scam Check</Link>
          <Link to="/scam-arena">Scam Arena</Link>
          <Link to="/family-shield">Family Shield</Link>
          <Link to="/#about">About</Link>
        </nav>
        <Link className="back-top" to="/">Back to top ↑</Link>
      </div>
      <div className="section-wrap footer-bottom"><span>© 2026 FORWARD? All rights reserved.</span><span>Stay curious. Stay safe.</span></div>
    </footer>
  )
}
