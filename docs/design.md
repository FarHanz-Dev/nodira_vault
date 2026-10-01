# Design

This document describes the on-disk formats and the key hierarchy so the
scheme can be reviewed without reading the code.

## 1. Single-file backup (`NodiraCryptoEngine`)

```
password ──PBKDF2-HMAC-SHA256(salt, 200000)──▶ key (32 B)
plaintext ──AES-256-GCM(key, iv)──▶ ciphertext ‖ tag (16 B)
```

The envelope is JSON: `version`, `kdf`, `iterations`, `salt` (16 B), `algorithm`,
`iv` (12 B, fresh per encryption), `ciphertext`, `authTag`, `createdAt`,
`appVersion` (base64 for binary fields). Everything needed to decrypt except the
password is inside the file.

Within one process the derived key (and its salt) is cached per password, so
repeated encryptions skip the KDF. A **new random IV is used every time**, which
keeps GCM safe far below NIST's 2^32-message-per-key limit.

## 2. Vault key hierarchy (`VaultCrypto`)

```
passphrase ──Argon2id(salt, 64 MiB, t=3, p=2)──▶ KEK
MK (32 random bytes, once per vault) ──AES-GCM(KEK, aad = vaultId)──▶ wrapped MK
MK ──HKDF("name")───────────────▶ K_name   (HMAC key for object names)
MK ──HKDF("obj:" ‖ objectId)────▶ K_obj    (one key per object)
```

### Keyring (the only object with a fixed name, `nodira.keyring`)

JSON: `v`, `id` (random vaultId), `kdf {m,t,p}`, `salt`, `mk` (wrapped master
key). It leaks only the KDF parameters, which must be public anyway.

### Sealed object

```
'NDV1' (4 B) ‖ objectId (16 B, random) ‖ AES-256-GCM(K_obj, gzip(plaintext)) ‖ tag
```

- The 20-byte header is authenticated as AAD.
- Compression happens **before** encryption (ciphertext is incompressible).
- Because every object has its own key derived from a fresh `objectId`, nonce
  reuse under a single key cannot occur, so a fixed zero IV is safe here.
- A truncated, edited, or foreign-vault object fails the GCM tag and raises
  `CORRUPTED_OBJECT`; it is never returned as plausible plaintext.

### Object names

`name = hex(HMAC-SHA256(K_name, logicalPath)[0..16])`. Deterministic, so two
devices compute the same name, but not reversible without the master key.

### Changing the passphrase

`VaultCrypto.rewrap` derives a new KEK from a fresh salt and re-wraps the same
MK. No object is rewritten.

## 3. Storage contract (`RemoteStore`)

`list`, `get`, `put` (must be idempotent), `delete`. There is no CAS. The
protocol avoids needing one: each device only writes objects it owns, and the
only shared object (the keyring) is written once at creation and never
overwritten.

## 4. Threat model in one paragraph

Defends against an attacker who can read and modify everything on the storage
provider, and against the provider itself. It does **not** defend against a
compromised device (keys live in memory while unlocked), a weak passphrase
(offline guessing is only slowed by Argon2id), or traffic analysis of object
sizes and counts.
