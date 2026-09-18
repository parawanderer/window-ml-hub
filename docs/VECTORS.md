# Test vectors: what a second implementation has to reproduce

`vectors/seal-v1.json` is what the extension's WebCrypto implementation (window-ml) and any other client are checked
against. Everything in it is hex. It exists because the two sides of this protocol are written twice, in Rust and in
the browser, and the first time they disagree should be in a test, not in somebody's session.

The Rust side reads the same file back (`crates/seal/tests/vectors.rs`), so the vectors and the implementation cannot
drift apart quietly: change how anything is signed, sealed or named and that test fails.

## What is in the file

| key | what it gives you |
| --- | --- |
| `suite` | the algorithms, every domain-separation label, and the time the vectors were made at |
| `account` | the account's root key (seed and public key) and the account id |
| `principals` | a runtime and a phone: identity seed and public key, principal id, agreement seed and public key, and the certificate the root issued each |
| `hello` | a challenge nonce, the transcript built from it, and the phone's signature over it |
| `command` | a sealed command from the phone to the runtime, with the plaintext, scope, nonce and HPKE info it was sealed under |
| `result` | the runtime's sealed result, naming the command's nonce |
| `grant` | a stream key wrapped for the phone, with the key, its id and the channel |
| `frame` | a published frame under that key, with the batch inside it |
| `channel_key`, `channels` | an account channel key and the names it produces for three purpose/subject pairs |

The filename names the PROTOCOL version (`wmlhub/v1`); the `version` field inside names the file's own revision, and
it is at **2**: every certificate now carries a validity window, which verifiers require, so a file at version 1 fails
against a current implementation rather than merely being old.

Seeds are given so an implementation can derive the same keys rather than importing raw private keys: an identity is
Ed25519 from its 32-byte seed, an agreement key is RFC 9180 `DeriveKeyPair` over its 32-byte seed.

## What to check, in the order a failure is easiest to read

1. **Key derivation.** From `identity_seed` and `agreement_seed`, reproduce `identity_public`, `principal_id`
   (SHA-256 of the identity public key) and `agreement_public`. If this is wrong, nothing below can work.
2. **Certificates.** Decode `certificate` (a `wmlhub.v1.Certificate`) and verify it under the account root:
   `"wmlhub/cert/v1" || 0x00 || body`. The body is verified exactly as transmitted, never re-encoded.
3. **Hello.** Rebuild the transcript from the hub name, challenge nonce, principal id, role and account id (lengths
   are 4-byte big-endian, see `hello_transcript`), compare it byte for byte with `hello.transcript`, and verify
   `hello.signature` under `"wmlhub/hello/v1"`.
4. **Channel names.** `channel_key` plus each entry's purpose and subject must give that entry's `channel`:
   HMAC-SHA256 over `"wmlhub/channel/v1" || 0x00 || purpose || 0x00 || subject`, truncated to 16 bytes.
5. **Command and result.** Open `command.sealed` as the runtime (HPKE base mode, its agreement key, info as given),
   check the chain and the signature (`"wmlhub/command/v1"`), and compare `body`, `scope` and `nonce`. Then open
   `result.sealed` as the phone and check it answers the command's nonce.
6. **Grant and frame.** Open `grant.sealed` as the phone (info `"wmlhub/keygrant/v1"`, signature
   `"wmlhub/grant/v1"`), check the key id is SHA-256 of `"wmlhub/streamkey-id/v1" || 0x00 || key` truncated to 8
   bytes, then open `frame.frame` under it: AES-256-GCM with the frame's nonce, the header as associated data, and
   the publisher's signature (`"wmlhub/stream/v1"`) over the header and ciphertext. The header is
   `publisher || len(channel) as 2 bytes big-endian || channel || key_id || counter as 8 bytes big-endian || nonce`.

The HPKE suite itself is checked separately against the RFC 9180 test vector for it, embedded in
`crates/seal/src/rfc9180_vector.rs`. Start there if the sealing does not open: it tells you whether the suite is right
before anything of ours is in the way.

## The other direction

`vectors/seal-ts-v1.json` is the other half: sealed by window-ml's TypeScript implementation (`src/hub`, over
WebCrypto) and opened here by `crates/seal/tests/vectors_ts.rs`. Both files are needed because neither HPKE nor Ed25519
lets randomness be replayed, so each side has to produce its own and the other has to open it.

Regenerate it from a window-ml checkout:

```bash
node --import tsx scripts/gen-hub-vectors.mjs > ../window-ml-hub/vectors/seal-ts-v1.json
```

It uses the parties `seal-v1.json` describes, from the same seeds, so the Rust test rebuilds the cast from its own
constants and only opens what the file carries.

## Regenerating

```bash
cargo test -p wmlhub-seal --test vectors write_vectors -- --ignored
```

Every seal draws fresh randomness, so the file changes wholesale each time. Regenerate only when the format changes on
purpose, and bump `version` when it does, so an implementation checking against an older file fails loudly rather than
silently testing nothing.
