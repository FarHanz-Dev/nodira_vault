# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Use GitHub's
private reporting: *Security → Report a vulnerability* on this repository. If
that is unavailable, contact the maintainer through the address on their GitHub
profile. Expect an acknowledgement within a few days.

## Scope and honest limits

- This library has **not been independently audited**. It composes standard
  primitives (AES-256-GCM, PBKDF2, Argon2id, HKDF, HMAC-SHA256) from
  `pointycastle`; the composition is what needs review.
- Argon2id is a custom implementation over native 64-bit `int` for speed on
  mobile. It is tested for byte-identical output against `pointycastle`'s
  implementation, not against every RFC 9106 vector.
- A passphrase is the only secret. **Forgetting it is unrecoverable by design.**
  A weak passphrase can be attacked offline by anyone who obtains the
  ciphertext; use a long one.
- `NodiraCryptoEngine` caches the derived key in process memory for the session
  (documented in `lib/src/crypto_engine.dart`). Call
  `NodiraCryptoEngine.clearKeyCache()` when you need to drop it.
- Dart gives no guarantee about zeroing memory; keys may linger in the heap.
- Integrity is authenticated (GCM), but the vault does not hide object *sizes*
  or *count* from the storage provider.

## Supported versions

Only the latest 0.x release receives fixes.
