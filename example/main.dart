// Runnable demo:  dart run example/main.dart
//
// 1. Encrypt/decrypt a single backup file with a password.
// 2. Create a vault, seal an object into an in-memory store, and open it again
//    from nothing but the passphrase (as a second device would).
import 'dart:convert';
import 'dart:typed_data';

import 'package:nodira_vault/nodira_vault.dart';

Future<void> main() async {
  // ── 1. Single-file backup (AES-256-GCM, PBKDF2-HMAC-SHA256) ────────────────
  final engine = NodiraCryptoEngine();
  final envelope =
      await engine.encrypt('{"balance": 1250000}', 'correct horse');
  final json = jsonEncode(envelope.toJson()); // safe to write to disk
  final back = await engine.decrypt(
      BackupEnvelope.fromJson(jsonDecode(json) as Map<String, dynamic>),
      'correct horse');
  print('backup round-trip: $back');

  // ── 2. Vault: passphrase -> keys -> sealed objects on dumb storage ─────────
  final store = MemoryRemoteStore();

  // Device A creates the vault. The keyring is the only object with a fixed
  // name; everything else is named by an HMAC, so the storage learns nothing.
  final (keyring, keys) = await VaultCrypto.create(
    'a long passphrase you will not forget',
    kdf:
        const VaultKdfParams.testOnly(), // use the default (64 MiB) in real use
  );
  await store.put(kKeyringName, keyring.toBytes());
  await store.put(
    keys.objectName('snapshots/device-a'),
    keys.seal(Uint8List.fromList(utf8.encode('secret ledger'))),
  );

  // Device B only has the passphrase.
  final fetched = VaultKeyring.fromBytes(await store.get(kKeyringName));
  final keysB = await VaultCrypto.unlock(
      fetched, 'a long passphrase you will not forget');
  final sealed = await store.get(keysB.objectName('snapshots/device-a'));
  print('vault round-trip: ${utf8.decode(keysB.open(sealed))}');

  print('objects on the server: ${(await store.list()).map((e) => e.name)}');
}
