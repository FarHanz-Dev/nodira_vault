// test/core/crypto/nodira_crypto_engine_test.dart
//
// 10 test cases wajib sesuai spesifikasi Nodira Encrypt/Decrypt Engine.
// Pure Dart — tidak ada Flutter widget, bisa jalan tanpa device/emulator.

import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:nodira_vault/nodira_vault.dart';

void main() {
  final engine = NodiraCryptoEngine();

  group('NodiraCryptoEngine', () {
    // ── 1. Roundtrip dasar ──────────────────────────────────────────────────

    test('encrypt lalu decrypt mengembalikan plaintext asli', () async {
      const plaintext = '{"transactions":[{"id":1,"amount":50000}]}';
      const password = 'password123';

      final envelope = await engine.encrypt(plaintext, password);
      final result = await engine.decrypt(envelope, password);

      expect(result, equals(plaintext));
    });

    // ── 2. Password salah terdeteksi ────────────────────────────────────────

    test('decrypt dengan password salah throw WRONG_PASSWORD', () async {
      const plaintext = '{"test": true}';

      final envelope = await engine.encrypt(plaintext, 'correct_password');

      expect(
        () => engine.decrypt(envelope, 'wrong_password'),
        throwsA(
          isA<NodiraCryptoException>().having(
            (e) => e.code,
            'code',
            'WRONG_PASSWORD',
          ),
        ),
      );
    });

    // ── 3. IV selalu unik ───────────────────────────────────────────────────

    test('dua enkripsi menghasilkan IV berbeda', () async {
      const plaintext = 'sama persis';
      const password = 'pw';

      final e1 = await engine.encrypt(plaintext, password);
      final e2 = await engine.encrypt(plaintext, password);

      expect(e1.iv, isNot(equals(e2.iv)));
    });

    // ── 4. Salt unik antar sesi/password ────────────────────────────────────
    // KONTRAK BARU (optimasi cache kunci per-sesi, 2026-07-20): dalam satu
    // sesi, password sama me-reuse salt+kunci (KDF sekali per sesi; aman
    // karena IV selalu baru — lihat header engine). Salt tetap unik antar
    // sesi (clearKeyCache) dan antar password.

    test('salt: reuse dalam sesi (by design), unik antar sesi & password',
        () async {
      const plaintext = 'sama persis';

      final e1 = await engine.encrypt(plaintext, 'pw');
      final e2 = await engine.encrypt(plaintext, 'pw');
      expect(e2.salt, equals(e1.salt),
          reason: 'sesi & password sama → salt cache di-reuse');

      NodiraCryptoEngine.clearKeyCache(); // simulasi sesi baru
      final e3 = await engine.encrypt(plaintext, 'pw');
      expect(e3.salt, isNot(equals(e1.salt)),
          reason: 'sesi baru → salt acak baru');

      final e4 = await engine.encrypt(plaintext, 'pw-lain');
      expect(e4.salt, isNot(equals(e3.salt)),
          reason: 'password beda → salt acak baru');
    });

    // ── 5. File tampered terdeteksi ─────────────────────────────────────────

    test('decrypt file yang dimodifikasi throw WRONG_PASSWORD', () async {
      final envelope = await engine.encrypt('{"amount":1000}', 'secret');

      // Modifikasi 1 byte di ciphertext
      final ciphertextBytes = base64.decode(envelope.ciphertext);
      ciphertextBytes[0] ^= 0xFF; // flip semua bit pada byte pertama
      final tampered = envelope.copyWith(
        ciphertext: base64.encode(ciphertextBytes),
      );

      expect(
        () => engine.decrypt(tampered, 'secret'),
        throwsA(
          isA<NodiraCryptoException>().having(
            (e) => e.code,
            'code',
            'WRONG_PASSWORD',
          ),
        ),
      );
    });

    // ── 6. File dengan format salah ─────────────────────────────────────────

    test('decrypt envelope dengan base64 tidak valid throw CORRUPTED_FILE',
        () async {
      final envelope = await engine.encrypt('data', 'pw');
      final corrupted = envelope.copyWith(ciphertext: '!!!bukan-base64!!!');

      expect(
        () => engine.decrypt(corrupted, 'pw'),
        throwsA(
          isA<NodiraCryptoException>().having(
            (e) => e.code,
            'code',
            'CORRUPTED_FILE',
          ),
        ),
      );
    });

    // ── 7. String kosong tetap bisa dienkripsi ──────────────────────────────

    test('enkripsi empty string berhasil dan roundtrip kembali ke empty',
        () async {
      const password = 'any_password';

      final envelope = await engine.encrypt('', password);
      final result = await engine.decrypt(envelope, password);

      expect(result, equals(''));
    });

    // ── 8. Data besar (simulasi 5MB JSON) ───────────────────────────────────

    test('enkripsi 5MB plaintext selesai dalam 10 detik', () async {
      // 500.000 karakter 'x' ≈ 500KB JSON — cukup untuk validasi performa
      // di environment CI/test (bukan device nyata). Limit longgar ke 10s.
      final bigJson = '{"data":"${List.generate(500000, (_) => 'x').join()}"}';

      final stopwatch = Stopwatch()..start();
      final envelope = await engine.encrypt(bigJson, 'testpassword');
      stopwatch.stop();

      // Verifikasi hasil bisa di-decrypt kembali
      final result = await engine.decrypt(envelope, 'testpassword');
      expect(result, equals(bigJson));

      expect(
        stopwatch.elapsedMilliseconds,
        lessThan(10000),
        reason: 'Enkripsi 5MB melebihi 10 detik di test environment',
      );
    }, timeout: const Timeout(Duration(seconds: 30)));

    // ── 9. Unicode password ─────────────────────────────────────────────────

    test('password dengan karakter unicode berhasil roundtrip', () async {
      const plaintext = '{"note":"data sensitif"}';
      const unicodePw = 'p@\$\$w0rd🔑日本語';

      final envelope = await engine.encrypt(plaintext, unicodePw);
      final result = await engine.decrypt(envelope, unicodePw);

      expect(result, equals(plaintext));
    });

    // ── 10. BackupEnvelope serialization roundtrip ──────────────────────────

    test('BackupEnvelope toJson/fromJson roundtrip sempurna', () async {
      final original = await engine.encrypt('{"x":1}', 'pw');
      final json = original.toJson();
      final restored = BackupEnvelope.fromJson(json);

      expect(restored.version, equals(original.version));
      expect(restored.kdf, equals(original.kdf));
      expect(restored.iterations, equals(original.iterations));
      expect(restored.salt, equals(original.salt));
      expect(restored.algorithm, equals(original.algorithm));
      expect(restored.iv, equals(original.iv));
      expect(restored.ciphertext, equals(original.ciphertext));
      expect(restored.authTag, equals(original.authTag));
      expect(restored.createdAt, equals(original.createdAt));
      expect(restored.appVersion, equals(original.appVersion));
    });
  });

  // ── Kompatibilitas format: backup PRA-optimasi tetap terbuka ──────────────
  // Envelope golden dihasilkan implementasi engine SEBELUM optimasi performa
  // 2026-07-20 (KDF-only-isolate, Fortuna RNG). JANGAN diubah.

  group('golden compat', () {
    const goldenEnvelopeJson =
        '{"version":1,"kdf":"PBKDF2","iterations":200000,'
        '"salt":"tg2sbYtuW7xMZUUFL7SHKA==","algorithm":"AES-256-GCM",'
        '"iv":"gyAqKDHWAq+yHdwh",'
        '"ciphertext":"J6w1t+N4w6mPIxLWBWnEbV7+mlj1EajEUIy9Uqc3/vfPkXi3HsRgVel8'
        '0OtfLNoak57GHKfM2k0MaCszN2vtLIIVoArLEIILbHD20e5fDYajqvY+EfyE5SrCVZOs9yqO",'
        '"authTag":"rh+6BZHF6+0WMZQ91nfCJw==",'
        '"createdAt":"2026-07-20T12:39:45.459029Z","appVersion":"1.0.0"}';
    const goldenPassword = 'S4ndi-Golden!';
    const goldenPlaintext =
        '{"tables":{"transactions":[{"id":1,"amount":150000}]},'
        '"note":"golden fixture — jangan diubah"}';

    test('envelope dari implementasi lama tetap terdekripsi', () async {
      NodiraCryptoEngine.clearKeyCache();
      final envelope = BackupEnvelope.fromJson(
          jsonDecode(goldenEnvelopeJson) as Map<String, dynamic>);
      expect(await engine.decrypt(envelope, goldenPassword), goldenPlaintext);
    });

    test('version di atas yang didukung → UNSUPPORTED_VERSION', () async {
      final envelope = BackupEnvelope.fromJson(
          jsonDecode(goldenEnvelopeJson) as Map<String, dynamic>);
      expect(
        () => engine.decrypt(envelope.copyWith(version: 99), goldenPassword),
        throwsA(isA<NodiraCryptoException>()
            .having((e) => e.code, 'code', 'UNSUPPORTED_VERSION')),
      );
    });
  });

  // ── Cache kunci per-sesi (optimasi 2026-07-20) ────────────────────────────

  group('cache kunci per-sesi', () {
    setUp(NodiraCryptoEngine.clearKeyCache);

    test('encrypt kedua dgn password sama: IV tetap baru, hasil valid',
        () async {
      final e1 = await engine.encrypt('{"n":1}', 'pwd-cache');
      final e2 = await engine.encrypt('{"n":2}', 'pwd-cache');
      expect(e2.iv, isNot(e1.iv), reason: 'IV wajib unik per enkripsi');
      expect(await engine.decrypt(e1, 'pwd-cache'), '{"n":1}');
      expect(await engine.decrypt(e2, 'pwd-cache'), '{"n":2}');
    });

    test('decrypt men-seed cache encrypt: backup pasca-restore reuse salt',
        () async {
      final envelope = await engine.encrypt('{"n":1}', 'pwd-seed');
      NodiraCryptoEngine.clearKeyCache();
      await engine.decrypt(envelope, 'pwd-seed');
      final next = await engine.encrypt('{"n":2}', 'pwd-seed');
      expect(next.salt, envelope.salt,
          reason: 'salt envelope di-reuse → KDF dilewati');
      expect(await engine.decrypt(next, 'pwd-seed'), '{"n":2}');
    });
  });

  // ── deriveKey unit test ─────────────────────────────────────────────────────

  group('NodiraCryptoEngine.deriveKey', () {
    test('output selalu 32 bytes', () {
      final key = NodiraCryptoEngine.deriveKey(
        'password',
        Uint8List.fromList(List.filled(16, 0)),
        1, // iterasi minimal untuk speed test
      );
      expect(key.length, equals(32));
    });

    test('salt berbeda menghasilkan key berbeda', () {
      final salt1 = Uint8List.fromList(List.filled(16, 0x01));
      final salt2 = Uint8List.fromList(List.filled(16, 0x02));

      final key1 = NodiraCryptoEngine.deriveKey('pw', salt1, 1);
      final key2 = NodiraCryptoEngine.deriveKey('pw', salt2, 1);

      expect(key1, isNot(equals(key2)));
    });

    test('deterministik — input sama selalu menghasilkan key sama', () {
      final salt = Uint8List.fromList(List.filled(16, 0xAB));

      final key1 = NodiraCryptoEngine.deriveKey('deterministic', salt, 100);
      final key2 = NodiraCryptoEngine.deriveKey('deterministic', salt, 100);

      expect(key1, equals(key2));
    });
  });
}
