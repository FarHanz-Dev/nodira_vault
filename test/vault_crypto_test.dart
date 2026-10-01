// Tests for the vault cryptography (keyring, key hierarchy, sealing).
// Passphrase-related strings are throwaway test data.
import 'dart:convert';
import 'dart:typed_data';

import 'package:nodira_vault/nodira_vault.dart';
import 'package:test/test.dart';

const _kdf = VaultKdfParams.testOnly();
const _pass = 'kuda-merah-tidur-di-atap-7';

Uint8List _b(String s) => Uint8List.fromList(utf8.encode(s));

void main() {
  group('kriptografi vault', () {
    test('buka dengan passphrase benar, tolak yang salah', () async {
      final (keyring, keys) = await VaultCrypto.create(_pass, kdf: _kdf);
      final sealed = keys.seal(_b('Gaji Rp 12.500.000'));

      final again = await VaultCrypto.unlock(
          VaultKeyring.fromBytes(keyring.toBytes()), _pass);
      expect(utf8.decode(again.open(sealed)), 'Gaji Rp 12.500.000');

      await expectLater(
        VaultCrypto.unlock(keyring, 'passphrase-lain'),
        throwsA(isA<VaultCryptoException>()
            .having((e) => e.code, 'code', 'WRONG_PASSPHRASE')),
      );
    });

    test('objek yang disunting satu byte pun DITOLAK', () async {
      final (_, keys) = await VaultCrypto.create(_pass, kdf: _kdf);
      final sealed = keys.seal(_b('isi rahasia'));
      final bad = Uint8List.fromList(sealed)..[sealed.length - 5] ^= 0x01;
      expect(
          () => keys.open(bad),
          throwsA(isA<VaultCryptoException>()
              .having((e) => e.code, 'code', 'CORRUPTED_OBJECT')));
    });

    test('plaintext sama tak pernah menghasilkan ciphertext sama', () async {
      final (_, keys) = await VaultCrypto.create(_pass, kdf: _kdf);
      final a = keys.seal(_b('sama persis'));
      final b = keys.seal(_b('sama persis'));
      expect(a, isNot(equals(b)),
          reason: 'kunci per objek wajib unik — IV nol aman HANYA karena itu');
    });

    test('vault lain tak bisa membuka objek vault ini', () async {
      final (_, k1) = await VaultCrypto.create(_pass, kdf: _kdf);
      final (_, k2) = await VaultCrypto.create(_pass, kdf: _kdf);
      expect(() => k2.open(k1.seal(_b('milik vault 1'))),
          throwsA(isA<VaultCryptoException>()));
    });

    test('nama objek deterministik & tak memuat jalur logisnya', () async {
      final (_, keys) = await VaultCrypto.create(_pass, kdf: _kdf);
      final n1 = keys.objectName('snap:hp-a:1');
      expect(n1, keys.objectName('snap:hp-a:1'));
      expect(n1, isNot(keys.objectName('snap:hp-a:2')));
      expect(n1, matches(RegExp(r'^[0-9a-f]{32}$')));
    });

    test('ganti passphrase: yang lama ditolak, isi lama tetap terbaca',
        () async {
      final (keyring, keys) = await VaultCrypto.create(_pass, kdf: _kdf);
      final sealed = keys.seal(_b('catatan lama'));
      final next =
          await VaultCrypto.rewrap(keyring, keys, 'passphrase-baru-99');

      await expectLater(VaultCrypto.unlock(next, _pass),
          throwsA(isA<VaultCryptoException>()));
      final reopened = await VaultCrypto.unlock(next, 'passphrase-baru-99');
      expect(utf8.decode(reopened.open(sealed)), 'catatan lama');
    });
  });
}
