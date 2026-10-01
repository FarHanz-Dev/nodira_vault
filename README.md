# nodira_vault

[![CI](https://github.com/FarHanz-Dev/nodira_vault/actions/workflows/ci.yml/badge.svg)](https://github.com/FarHanz-Dev/nodira_vault/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Pure-Dart, client-side encryption for personal-finance data. Extracted from
[Nodira](https://github.com/FarHanz-Dev), an offline-first finance app, where it
protects local backups and an optional encrypted vault on the user's own Google
Drive.

Everything is encrypted **on the device before it leaves it**. The storage
provider only ever sees opaque bytes and opaque names.

> **Status: 0.x, not independently audited.** The primitives come from
> [`pointycastle`](https://pub.dev/packages/pointycastle) and the construction
> is deliberately conventional, but the composition has not had a third-party
> review. Read [SECURITY.md](SECURITY.md) and [docs/design.md](docs/design.md)
> before relying on it for anything you cannot afford to lose.

## What is in the box

| Component | Purpose | Primitives |
|---|---|---|
| `NodiraCryptoEngine` | Encrypt a single backup file with a password | PBKDF2-HMAC-SHA256 (200,000 iterations) → AES-256-GCM |
| `VaultCrypto`, `VaultKeys`, `VaultKeyring` | Key hierarchy for a multi-object vault | Argon2id (64 MiB) → KEK → random master key → HKDF per-object keys → AES-256-GCM |
| `RemoteStore` | The tiny interface a storage backend implements (`list`/`get`/`put`/`delete`) | none |
| `MemoryRemoteStore` | Reference backend for tests and demos | none |

Design goals for the vault:

- **Zero knowledge.** Lose the passphrase and the data is random bytes. There is
  no reset, because a reset would mean the operator can read it.
- **Dumb storage is enough.** No compare-and-swap, no locking, no server logic.
  Drive, SAF, WebDAV or a folder all qualify. Each device writes only its own
  objects.
- **Metadata-blind.** Object names are `HMAC(K_name, logicalPath)`, so names such
  as `snapshot-2026-09-25` never leak *when* you were active.
- **Nonce-misuse resistant by construction.** Every object gets its own key, so
  a repeated nonce can never happen under the same key.
- **Change passphrase without re-encrypting.** Only the wrapped master key is
  replaced (`VaultCrypto.rewrap`).

## Usage

```yaml
dependencies:
  nodira_vault:
    git:
      url: https://github.com/FarHanz-Dev/nodira_vault
```

### Encrypt a single file

```dart
final engine = NodiraCryptoEngine();
final envelope = await engine.encrypt(jsonString, password);
final plain = await engine.decrypt(envelope, password); // throws NodiraCryptoException
```

Errors are typed (`WRONG_PASSWORD`, `CORRUPTED_FILE`, `UNSUPPORTED_VERSION`,
`UNKNOWN`); nothing else escapes.

### A vault on any storage

```dart
final store = MemoryRemoteStore(); // or your own RemoteStore implementation

// Device A
final (keyring, keys) = await VaultCrypto.create(passphrase);
await store.put(kKeyringName, keyring.toBytes());
await store.put(keys.objectName('snapshots/device-a'), keys.seal(bytes));

// Device B: only the passphrase is needed
final keysB = await VaultCrypto.unlock(
    VaultKeyring.fromBytes(await store.get(kKeyringName)), passphrase);
final plain = keysB.open(await store.get(keysB.objectName('snapshots/device-a')));
```

A complete runnable version is in [`example/main.dart`](example/main.dart).

## Requirements and limits

- Dart SDK `^3.6`. **VM / AOT only** (Flutter mobile, desktop, server). The
  Argon2id implementation relies on native 64-bit `int` wrap-around and the
  package uses `dart:io` (`gzip`), so it does not target the web.
- Heavy work (KDF, GCM over large payloads) runs in a short-lived isolate via
  `Isolate.run`, so it will not block a UI thread.
- The default Argon2id cost is 64 MiB × 3 passes × 2 lanes. Parameters are
  stored in the keyring, so raising them later does not break existing vaults.

## Development

```bash
dart pub get
dart analyze
dart test
dart run example/main.dart
```

The test suite includes byte-for-byte cross-checks of the Argon2id
implementation against `pointycastle`, tamper-detection tests, and a golden
envelope from the original implementation to guard format compatibility.

## Notes on the source

The code was extracted from an Indonesian-language application, so many
in-code comments are written in Indonesian. Identifiers, this documentation,
and error codes are in English. Translations of comments are welcome as pull
requests.

## License

[MIT](LICENSE)
