# Changelog

## 0.1.0

- Initial public release, extracted from the Nodira app.
- `NodiraCryptoEngine`: password-encrypted single-file backups
  (PBKDF2-HMAC-SHA256 200k → AES-256-GCM), format version 1.
- `VaultCrypto` / `VaultKeys` / `VaultKeyring`: Argon2id key hierarchy with
  per-object keys and HMAC-derived object names.
- `RemoteStore` interface and `MemoryRemoteStore`.
- Pure-Dart `compute` replacement (`Isolate.run`); no Flutter dependency.
