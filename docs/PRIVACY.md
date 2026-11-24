# Privacy and security notes

## Application behavior inspected

- Message rules analyze text in the browser. The inspected source contains no application API call for message submission.
- URL analysis parses the supplied value with the browser's `URL` implementation and performs local checks. It does not open or expand the submitted address and does not query a reputation service.
- Screenshot analysis passes the selected `File` to a Tesseract.js worker created in the browser. The inspected app source contains no screenshot upload endpoint or application-controlled image transmission.
- The page clears its `File` state after OCR completes, reset, cancellation, switching away from screenshot input, and route unmount. The component clears the file input value after selection. The OCR worker is terminated in `finally` and cancellation paths.
- No `localStorage` or `sessionStorage` use, `fetch`, `XMLHttpRequest`, `axios`, or `dangerouslySetInnerHTML` use was found in the inspected `src` files.

## External browser resources

Local processing does not mean the browser makes no network requests. `src/index.css` imports DM Sans, Space Grotesk, and DM Mono from Google Fonts. Tesseract.js may retrieve its worker/runtime and English recognition data from its configured/default resource locations on first use. These are resource downloads; they are distinct from uploading the user's screenshot. This review did not perform packet capture or inspect every browser network request, so it cannot certify all network traffic at the transport layer.

## User guidance and limitations

The interface advises users to remove names, account details, or codes before pasting a message. Screenshots are kept in transient page state for the current check and removed when the analysis completes or is cleared. Do not paste secrets into a shared or untrusted device. OCR is English-oriented and can misread text. No analysis result confirms the sender or proves a link is safe or fraudulent.

## Scope

These notes are based on source inspection and browser-level checks described in the project QA report, not a penetration test, packet capture, or formal privacy certification. Review this document when changing analytics, fonts, OCR hosting, storage, APIs, or deployment configuration.
