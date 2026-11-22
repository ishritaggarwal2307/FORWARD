# FORWARD? design direction

## Product and audience

FORWARD? helps people recognise online scams, understand suspicious digital interactions, and build safer habits. The homepage speaks to everyday internet users and introduces three experiences: Scam Check, Scam Arena, and Family Shield. Those experiences are presented as upcoming; this site does not claim their tools are functional.

## Visual identity

- **Midnight Black `#0B0D12`** is the primary canvas, for a calm, focused digital-safety setting.
- **Electric Cobalt Blue `#315BEB`** marks explanation and guidance.
- **Acid Lime `#C5F451`** marks attention, action, and detected signals.
- **Soft White `#F4F5F7`** provides high-contrast reading surfaces.
- Display typography uses Space Grotesk; body text uses DM Sans; short interface labels use DM Mono. System sans-serif and monospace fallbacks keep the page usable if web fonts cannot load.

## Layout signature

The homepage is a hybrid brand and product surface: the dark hero establishes the brand, the white warning-sign and habit sections prioritize reading, and the dark experience cards introduce the product paths. The signature illustration is a suspicious message with its sender/link mismatch called out; it uses CSS and text, not stock imagery. Hairline borders and square corners make the page feel precise. Lime is reserved for primary actions and caution signals.

## Runtime mapping

The palette, type stacks, content width, borders, focus, scrollbar, and reduced-motion behavior are implemented as CSS custom properties and global rules in `src/index.css`. Page-level layout and responsive component styles live in `src/App.css`. Keep new homepage sections on these tokens; do not introduce a second palette or motion convention.

## Interaction and accessibility

Use semantic links for navigation, maintain visible keyboard focus, provide a skip link, and retain the native disclosure behavior for the narrow-screen menu. Homepage feature CTAs navigate to `/scam-check`, `/scam-arena`, and `/family-shield`. Honor `prefers-reduced-motion`; keep `/#about` as the homepage About anchor.

## Scam Check product surface

The `/scam-check` route reuses the homepage header, footer, palette, typography, square corners, and restrained borders. Keep its input method, analysis, and result components inside `src/features/scam-check/`; keep rules and result types separate from UI. Risk wording must stay explainable, avoid accuracy scores, and never imply that no detected signals means safe. Screenshot OCR is English-only and local to the browser; selected image data is cleared after review, reset, or route exit. Tesseract may fetch its runtime and language data on first use, but the screenshot itself is not uploaded.
