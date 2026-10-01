/// Client-side encryption for personal-finance backups and a "bring your own
/// storage" encrypted vault.
///
/// * [NodiraCryptoEngine] — passphrase-encrypted single-file backups
///   (AES-256-GCM, PBKDF2-HMAC-SHA256).
/// * [VaultCrypto] / [VaultKeys] / [VaultKeyring] — the vault key hierarchy
///   (Argon2id → KEK → master key → per-object keys, HKDF-derived).
/// * [RemoteStore] — the tiny storage interface a backend must implement, plus
///   an in-memory reference implementation ([MemoryRemoteStore]).
library;

export 'src/crypto_engine.dart';
export 'src/remote_store.dart';
export 'src/vault_crypto.dart';
