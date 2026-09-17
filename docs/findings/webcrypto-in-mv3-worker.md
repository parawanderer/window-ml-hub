# Finding: what WebCrypto an MV3 service worker has

**Answered 2026-09-17**, Chrome for Testing 151.0.7922.34 (headless, macOS arm64), inside an extension service worker,
which is where the hub connector holds keys (keys never reach the page). Probe: `tools/webcrypto-probe/probe.mjs`.

| Operation | Result |
| --- | --- |
| Ed25519 generate, sign, verify | works |
| Ed25519 private key generated non-extractable | stays non-extractable (`exportKey` refused) |
| X25519 generate, `deriveBits` (both sides agree) | works |
| X25519 raw public key export | 32 bytes |
| AES-256-GCM encrypt and decrypt | works |
| HKDF-SHA256, HMAC-SHA256, SHA-512 | work |
| ECDSA P-256 | works |
| A non-extractable `CryptoKey` stored in IndexedDB and used after reading it back | works |
| **ChaCha20-Poly1305** | **not supported** (`NotSupportedError: Unrecognized name`) |

## What it means

- **Everything an HPKE-style design needs is native**: X25519 for key agreement, HKDF-SHA256, AES-256-GCM, Ed25519
  for signatures. No WebAssembly or JavaScript crypto library is required in the worker.
- **Private keys can be unusable as bytes even to the extension's own code**: generated non-extractable and stored as
  `CryptoKey` objects in IndexedDB, they can sign and derive but cannot be read out. A bug or injected script in the
  extension can misuse a key while it runs, but cannot copy it elsewhere. A JavaScript crypto library cannot offer
  this, because it holds keys as byte arrays.
- **Anything built on ChaCha20-Poly1305 or XSalsa20-Poly1305** (libsodium's `crypto_box`, the ChaCha Noise suites)
  would need a bundled implementation in the worker and would give up non-extractable keys.
- **WebCrypto cannot convert an Ed25519 key to X25519**, so a principal holds two keypairs, the X25519 one bound to
  the Ed25519 identity by a signature.

Re-run on a new major Chrome before relying on a primitive not listed here.
