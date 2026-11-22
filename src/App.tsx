import { useEffect } from 'react'
import { Link, Route, Routes, useLocation } from 'react-router-dom'
import { SiteFooter, SiteHeader } from './components/SiteHeader'
import ScamCheckPage from './features/scam-check/ScamCheckPage'
import HomePage from './pages/HomePage'

function ComingSoonPage({ feature }: { feature: string }) {
  useEffect(() => { document.title = `${feature} | FORWARD?` }, [feature])

  return (
    <section className="coming-soon-page section-wrap" aria-labelledby="coming-soon-title">
      <p className="eyebrow"><span className="eyebrow-line" /> MORE WAYS TO STAY READY</p>
      <h1 id="coming-soon-title">{feature}<br /><span>is on the way.</span></h1>
      <p>We’re building this experience. In the meantime, check a suspicious message with FORWARD?.</p>
      <Link className="button button-lime" to="/scam-check">Go to Scam Check <span className="arrow" aria-hidden="true">↗</span></Link>
    </section>
  )
}

function NotFoundPage() {
  useEffect(() => { document.title = 'Page not found | FORWARD?' }, [])

  return (
    <section className="coming-soon-page section-wrap" aria-labelledby="not-found-title">
      <p className="eyebrow"><span className="eyebrow-line" /> PAGE NOT FOUND</p>
      <h1 id="not-found-title">Let’s get you<br /><span>back on track.</span></h1>
      <p>That address doesn’t lead to a FORWARD? page.</p>
      <Link className="button button-lime" to="/">Return home <span className="arrow" aria-hidden="true">↗</span></Link>
    </section>
  )
}

function ScrollManager() {
  const { pathname, hash } = useLocation()

  useEffect(() => {
    if (hash) {
      let hashId: string
      try {
        hashId = decodeURIComponent(hash.slice(1))
      } catch {
        return
      }
      document.getElementById(hashId)?.scrollIntoView()
    } else {
      window.scrollTo(0, 0)
    }
  }, [pathname, hash])

  return null
}

function App() {
  return (
    <>
      <ScrollManager />
      <a className="skip-link" href="#main-content">Skip to content</a>
      <SiteHeader />
      <main id="main-content">
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/scam-check" element={<ScamCheckPage />} />
          <Route path="/scam-arena" element={<ComingSoonPage feature="Scam Arena" />} />
          <Route path="/family-shield" element={<ComingSoonPage feature="Family Shield" />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </main>
      <SiteFooter />
    </>
  )
}

export default App
