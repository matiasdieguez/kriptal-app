# Kriptal

Kriptal is an offline-first, vanilla JavaScript PWA for exchanging encrypted messages and public identities as files. There is no server, account system, inbox, or send/receive service. Users share the generated files through their device's native share sheet where supported, or download them to share manually.

Identity exports contain public keys only. Encrypted-message exports contain the signed, encrypted message payload. Recipients import identity files from Contacts and open message files from Open message. Previously shared identity and message links are still supported.

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

The tests cover vault persistence and a complete two-user identity-file exchange, message-file sharing, signature verification, and decryption flow.

## GitHub Pages

Pushes to `main` are tested and deployed automatically to [matiasdieguez.github.io/kriptal-app](https://matiasdieguez.github.io/kriptal-app/). In the repository settings, set **Pages > Build and deployment > Source** to **GitHub Actions** once. Pull requests run CI but do not deploy.

The Pages workflow builds with `BASE_PATH=/kriptal-app/`; local builds continue to use the root path by default.

## Security model

- The local vault is encrypted in `localStorage` with a password-derived AES-256-GCM key using PBKDF2-SHA-256.
- Identities use P-256 ECDH, ML-KEM-768, and ML-DSA-65 signing. Each message uses a fresh ephemeral P-256 key, ML-KEM encapsulation, HKDF, and AES-256-GCM.
- Incoming messages must match the saved contact's public keys and pass signature verification. Messages expire after seven days and are locally marked as consumed after successful decryption.
- Existing public-identity and encrypted-message links contain their payload in the URL hash, so it is not sent in normal HTTP requests. New exports use files to avoid messaging services truncating long links.
- ML-KEM-768 and ML-DSA-65 are standardized post-quantum primitives from FIPS 203 and FIPS 204. The hybrid design retains P-256 as defense in depth; the app requires a browser-capable bundled implementation and does not depend on a server.
- Message text is capped at 10 KB and attachments at 50 KB. Files are shared only when the user explicitly chooses the native share action or downloads them.

The password is never recoverable. Erasing local storage or losing the password makes the local identity unavailable.
