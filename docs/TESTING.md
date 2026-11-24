# Testing and local QA

## Automated checks

Run these from Windows PowerShell at the repository root:

```powershell
npm.cmd test
npm.cmd run build
npm.cmd run lint
git diff --check
```

The test command uses Node's built-in test runner with TypeScript stripping to test message rules, URL analysis, OCR extraction-quality decisions, worker errors and cancellation. OCR-worker tests are mocked; they do not prove that a real browser successfully downloads Tesseract's runtime or language data.

## Manual route walkthrough

Start the Vite development server:

```powershell
npm.cmd run dev -- --host 127.0.0.1
```

Open the printed local address and verify:

1. Homepage links reach Scam Check, Scam Arena, Family Shield, and About.
2. Scam Arena and Family Shield identify themselves as Coming Soon.
3. Scam Check message and URL submissions show findings, recommendations, and limitations; try Reset.
4. In screenshot mode, select a supported image, remove it, and test a local English screenshot. Stop and clear during OCR to test cancellation.
5. Use browser Back and Forward between routes.
6. Use keyboard-only navigation, including the skip link and mobile menu; verify visible focus and announcements of form errors and results.
7. Inspect layout at 375, 390, 430, 768, 1024, and 1440 CSS pixels. Check document width against viewport width for horizontal overflow.

## Test-data principles

Include both suspicious examples and close legitimate controls. Useful controls include ordinary conversations that say "urgent" or "verify," routine bank and KYC notifications, scheduled maintenance, workplace raffles, legitimate promotions, ordinary HTTPS and internationalized domains, and educational or negated scam examples. Review finding ID, strength, evidence, and final category rather than only whether the test exits successfully.

## OCR manual test notes

Use a clear English screenshot containing at least three readable words and more than 18 meaningful characters. Also test a blank/low-text image and a blurry or tiny-text image. Expected unreadable cases are Inconclusive. The app is English-oriented; do not treat OCR output or its recognition confidence as scam-detection confidence. The browser may need internet access to retrieve Tesseract runtime and English language assets on first use.
