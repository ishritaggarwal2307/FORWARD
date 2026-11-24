# Architecture

FORWARD? is a client-side React application. `src/main.tsx` mounts the app inside `BrowserRouter`; `src/App.tsx` owns the route table, shared header/footer shell, skip link, page title handling, and scroll behavior.

## Application routes

| Path | Page | State |
| --- | --- | --- |
| `/` | Homepage | Implemented |
| `/scam-check` | Scam Check | Implemented as local heuristic review |
| `/scam-arena` | Scam Arena | Coming Soon placeholder |
| `/family-shield` | Family Shield | Coming Soon placeholder |
| other | Not Found | Friendly recovery page |

## Scam Check flow

`ScamCheckPage.tsx` owns transient form state and selects one input mode. It calls the analysis modules and renders a typed `AnalysisResult`:

- `analysis/analyzeText.ts` applies contextual, explainable message rules.
- `analysis/analyzeUrl.ts` uses the browser `URL` parser and local structural checks. It performs no request to the submitted destination.
- `analysis/analyzeScreenshot.ts` validates image type, bytes and dimensions, creates an English Tesseract worker in the browser, handles cancellation, and passes extracted text to `analyzeMessage`.
- `analysis/types.ts` defines input modes, four result categories, findings, strengths, and optional high-concern triggers.
- `analysis/results.ts` classifies findings and provides shared limitations and inconclusive results.
- `components/` contains the input-mode picker and file-selection UI. The feature stylesheet is `ScamCheck.css`.

Detection code is kept separate from presentation code. Message and URL findings explain the signal and include evidence snippets where available. Informational observations remain visible but do not elevate risk. A High Concern result is reserved for direct authentication-secret requests or combinations explicitly marked as such.

## Styling

Global palette, type stacks, focus treatment, reduced-motion behavior, and shared tokens are in `src/index.css`. Homepage, navigation, footer, and shared route layout rules are in `src/App.css`. Scam Check layout and result rules are in `src/features/scam-check/ScamCheck.css`. `DESIGN.md` records the approved visual language.

## Adding a feature

1. Keep domain logic in a feature-specific module, not in a React component.
2. Add or extend TypeScript types for data crossing module boundaries.
3. Add deterministic tests for positive examples and legitimate/educational negative controls.
4. Present findings as signals, never as proof of fraud or safety.
5. Keep routing, privacy, keyboard interaction, and narrow layouts in mind.
