# Kriptal

Kriptal is an offline-first, vanilla JavaScript PWA for turning messages and files into encrypted links. There is no server, account system, inbox, or send/receive service. Users choose how to share the generated link.

## Run locally

```bash
npm install
npm run dev
```

Build the static PWA with `npm run build`. The production output is in `dist/` and can be hosted by any static file server.

Run the browser tests with Playwright:

```bash
npx playwright install chromium
npm test
```

The tests cover vault persistence and a complete two-user identity exchange, encryption, link opening, signature verification, and decryption flow.

## Security model

- The local vault is encrypted in `localStorage` with a password-derived AES-256-GCM key using PBKDF2-SHA-256.
- Identities use P-256 ECDH, ML-KEM-768, and ML-DSA-65 signing. Each message uses a fresh ephemeral P-256 key, ML-KEM encapsulation, HKDF, and AES-256-GCM.
- Incoming messages must match the saved contact's public keys and pass signature verification. Message links expire after seven days and are locally marked as consumed after successful decryption.
- Public identity links and encrypted message links contain their payload in the URL hash, so it is not sent in normal HTTP requests.
- QR generation uses `qrcode`; QR image import uses `jsQR`. Both are bundled locally for offline use.
- ML-KEM-768 and ML-DSA-65 are standardized post-quantum primitives from FIPS 203 and FIPS 204. The hybrid design retains P-256 as defense in depth; the app requires a browser-capable bundled implementation and does not depend on a server.
- Links are intentionally limited in size: message text is capped at 10 KB and attachments at 50 KB. URLs can leak through browser history, clipboard managers, screenshots, and the sharing channel.

The password is never recoverable. Erasing local storage or losing the password makes the local identity unavailable.
