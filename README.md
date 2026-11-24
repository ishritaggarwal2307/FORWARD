# FORWARD?

FORWARD? is a privacy-conscious scam-awareness prototype. It helps people pause over suspicious messages, web addresses, and screenshots, then review explainable warning indicators and practical next steps.

> **Important:** FORWARD provides heuristic scam-awareness assistance. Its findings are not proof of fraud, and the absence of warnings does not establish that a message or URL is safe.

## Current features

- **Scam Check** (`/scam-check`): rule-based review of pasted message text, one submitted URL, or an uploaded screenshot using English OCR in the browser.
- **Home** (`/`): product introduction and illustrative suspicious-message example, clearly labelled as a demonstration rather than a live scan.
- **Scam Arena** (`/scam-arena`) and **Family Shield** (`/family-shield`): clearly labelled Coming Soon pages.

The message and URL analyzers use local rules. URL review parses the supplied address but does not visit it, expand shortened links, or query a threat-intelligence service. Screenshot OCR extracts text locally and sends the extracted text through the same message rules.

## Technology

- React 19 and TypeScript 7
- Vite 8
- React Router
- Tesseract.js for browser-based English OCR
- Oxlint and Node's built-in test runner
- CSS (no component framework)

## Project structure

```text
src/
  App.tsx                         Routes and shared page shell
  components/SiteHeader.tsx       Shared navigation and footer
  pages/HomePage.tsx              Homepage
  features/scam-check/
    ScamCheckPage.tsx             Scam Check form and results UI
    components/                   Input method and screenshot upload
    analysis/                     Message, URL, OCR, result and type logic
  App.css                         Homepage, shell and responsive styles
  index.css                       Global design tokens and accessibility styles
tests/
  scam-check-analysis.test.mjs    Analyzer regression tests
docs/
  ARCHITECTURE.md
  TESTING.md
  PRIVACY.md
```

## Requirements and setup

Install Node.js compatible with Vite 8 (Node 20.19+ or 22.12+ recommended) and npm. From Windows PowerShell, in the project directory:

```powershell
npm.cmd ci
npm.cmd run dev
```

Open the local URL printed by Vite (normally `http://localhost:5173`). The app is a client-side prototype and does not require a backend or environment variables.

## Development checks

```powershell
npm.cmd test
npm.cmd run build
npm.cmd run lint
git diff --check
```

`npm.cmd run preview` serves a production build locally after `npm.cmd run build`.

## Privacy approach

Message and URL analysis run in the browser. The submitted URL is parsed locally and never opened by the analyzer. Screenshot pixels are passed to a local Tesseract worker; the application has no upload endpoint or backend. The UI clears the screenshot after analysis, reset, cancellation, or leaving Scam Check. Tesseract's runtime and English language resources can be downloaded the first time OCR is used, and the global stylesheet imports fonts from Google Fonts. See [the privacy review](docs/PRIVACY.md) for scope and limitations.

## Known limitations

- Detection is heuristic and English-oriented; it can miss paraphrases, multilingual content, context, or newly emerging scam patterns, and it can flag legitimate content.
- It does not verify sender identity, contact an institution, prove fraud, or determine that content is safe.
- URL structure checks do not establish site reputation. The registered-domain estimate uses a small local suffix list, not a complete public-suffix database.
- Screenshot OCR may misread or miss small, blurry, stylized, handwritten, or non-English text. OCR readability is not a scam-risk score.
- Scam Arena and Family Shield are not implemented yet.

## Future improvements

Potential next steps include a larger independently reviewed test corpus, a more complete public-suffix implementation if needed, multilingual OCR evaluation, and user testing with assistive technology. These should preserve local-first processing and the existing explainable result model.

## License

No license is currently specified in this repository.
