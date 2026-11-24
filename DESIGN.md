# FORWARD? design direction

## Product and audience

FORWARD? helps people recognise online scams, understand suspicious digital interactions, and build safer habits. The homepage introduces the available Scam Check experience and clearly labels Scam Arena and Family Shield as upcoming. Scam Check supports suspicious message text, URLs, and screenshots with browser-based English OCR. Its heuristic findings explain observed warning signs; they do not prove fraud or establish that content is safe.

## Visual identity

- **Midnight Black `#0B0D12`** is the primary canvas, for a calm, focused digital-safety setting.
- **Electric Cobalt Blue `#315BEB`** marks explanation and guidance.
- **Acid Lime `#C5F451`** marks attention, action, and detected signals.
- **Soft White `#F4F5F7`** provides high-contrast reading surfaces.
- Display typography uses Space Grotesk; body text uses DM Sans; short interface labels use DM Mono. System sans-serif and monospace fallbacks keep the page usable if web fonts cannot load.

## Layout signature

The homepage is a hybrid brand and product surface: the dark hero establishes the brand, the white warning-sign and habit sections prioritize reading, and dark experience cards introduce the product paths. The hero's suspicious-message illustration is explicitly marked as an illustrative example, not a live scan. It uses CSS and text rather than stock imagery. Hairline borders and square corners keep the visual language precise. Lime signals primary actions and salient status; the restrained cobalt is used for explanation.

## Runtime mapping

Palette, typography, content width, borders, focus, scrollbar, and reduced-motion behavior are implemented as CSS custom properties and global rules in `src/index.css`. Page-level layout and responsive component styles live in `src/App.css`; Scam Check styles live alongside that feature. Keep additions on the existing tokens and avoid a second palette or motion convention.

## Navigation and interaction

The shared header links to Home (`/`), Scam Check (`/scam-check`), Scam Arena (`/scam-arena`), Family Shield (`/family-shield`), and the homepage About anchor (`/#about`). The primary header and hero actions lead to the working Scam Check route. The homepage experience cards link Scam Check to its tool and link the two upcoming experiences to their clearly labelled Coming Soon pages. Use semantic links, maintain visible keyboard focus, provide the skip link, and retain the native disclosure behavior for the narrow-screen menu. Honor `prefers-reduced-motion`.

## Scam Check product surface

The `/scam-check` route reuses the homepage header, footer, palette, typography, square corners, and restrained borders. Input, analysis, and result components live inside `src/features/scam-check/`; rules and result types remain separate from UI. Risk wording stays explainable, avoids accuracy scores, and never implies that no detected signals means safe. Screenshot OCR is English-only and runs in the browser; selected image data is cleared after review, reset, cancellation, or route exit. Tesseract may fetch its runtime and English language data on first use, but the screenshot itself is not uploaded by the application.

## Feature status

- **Scam Check:** implemented for message, URL, and screenshot inputs. Real OCR has automated coverage, but has not been verified through a real screenshot in standard Chrome.
- **Scam Arena:** upcoming; the current route is a Coming Soon page.
- **Family Shield:** upcoming; the current route is a Coming Soon page.
