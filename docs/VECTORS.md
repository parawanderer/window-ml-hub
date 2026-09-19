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
| `renewal` | a laptop that may pair, an EXPIRED certificate the root gave a phone `approve`, and the laptop's renewal of it |
| `revocation` | a list the one principal holding `may_revoke` signed, naming the phone entirely and the approver's old certificate by hash |
| `hello` | a challenge nonce, the transcript built from it, and the phone's signature over it |
| `command` | a sealed command from the phone to the runtime, with the plaintext, scope, nonce and HPKE info it was sealed under |
| `result` | the runtime's sealed result, naming the command's nonce |
| `grant` | a stream key wrapped for the phone, with the key, its id and the channel |
| `frame` | a published frame under that key, with the batch inside it |
| `channel_key`, `channels` | an account channel key and the names it produces for three purpose/subject pairs |

The filename names the PROTOCOL version (`wmlhub/v1`); the `version` field inside names the file's own revision, and
it is at **4**: certificates carry a validity window (2), there is a `renewal` to check against (3), and a
`revocation` list (4). The
number exists so an old file fails loudly rather than passing incompletely: an implementation that passes a version 2
file has not been checked against the rule that lets a delegate re-issue a scope only the root may grant, and will
refuse a device that was renewed rather than re-paired.

Seeds are given so an implementation can derive the same keys rather than importing raw private keys: an identity is
Ed25519 from its 32-byte seed, an agreement key is RFC 9180 `DeriveKeyPair` over its 32-byte seed.

## What to check, in the order a failure is easiest to read

1. **Key derivation.** From `identity_seed` and `agreement_seed`, reproduce `identity_public`, `principal_id`
   (SHA-256 of the identity public key) and `agreement_public`. If this is wrong, nothing below can work.
2. **Certificates.** Decode `certificate` (a `wmlhub.v1.Certificate`) and verify it under the account root:
   `"wmlhub/cert/v1" || 0x00 || body`. The body is verified exactly as transmitted, never re-encoded.
3. **Renewal.** Verify `[renewal.renewed, renewal.delegate]` under the account root at `renewal.verify_at_ms`. It
   must succeed and the leaf must hold `renewal.scopes` (`approve`), which only the root may grant -- the laptop
   could not have issued that certificate and may re-issue it, because `renewed` carries the root's own
   `renewal.before` inside it. Three things a verifier has to get right, each with its own way of passing by
   accident: `before` is EXPIRED at `verify_at_ms` and its window must not be checked; `before` must verify under
   the ACCOUNT ROOT and not under the delegate; and every field of `renewed` except the issuer and the window must
   equal `before`'s, `agreement_key` above all, since that is where sealed commands go. Verifying `before` on its
   own at that time must FAIL, which is what makes the first of those three real.
4. **Revocation.** Verify `revocation.list` under the account root at `revocation.verify_at_ms`, holding no list. Its
   signer's chain must verify at that time and its leaf must carry `may_revoke`; the signature is over
   `"wmlhub/revocation/v1" || 0x00 || body`. It must name `revocation.principals` (principal ids) and
   `revocation.certificates` (SHA-256 of a certificate body exactly as transmitted, here the approver's `before`).
   Then SIGN the same body with the key from `revoker_seed` and compare: Ed25519 is deterministic, so a runtime that
   signs lists must reproduce `list` byte for byte. Two rules the vector does not exercise and a verifier needs anyway:
   a chain is revoked if ANY certificate in it is named, so a revoked delegate takes the devices it paired with it; and
   a renewal is revoked when the certificate it renews is.
5. **Hello.** Rebuild the transcript from the hub name, challenge nonce, principal id, role and account id (lengths
   are 4-byte big-endian, see `hello_transcript`), compare it byte for byte with `hello.transcript`, and verify
   `hello.signature` under `"wmlhub/hello/v1"`.
6. **Channel names.** `channel_key` plus each entry's purpose and subject must give that entry's `channel`:
   HMAC-SHA256 over `"wmlhub/channel/v1" || 0x00 || purpose || 0x00 || subject`, truncated to 16 bytes.
7. **Command and result.** Open `command.sealed` as the runtime (HPKE base mode, its agreement key, info as given),
   check the chain and the signature (`"wmlhub/command/v1"`), and compare `body`, `scope` and `nonce`. Then open
   `result.sealed` as the phone and check it answers the command's nonce.
8. **Grant and frame.** Open `grant.sealed` as the phone (info `"wmlhub/keygrant/v1"`, signature
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
