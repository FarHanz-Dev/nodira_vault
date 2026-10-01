// lib/src/crypto_engine.dart
// Pure Dart — zero Flutter dependency (kecuali compute dari foundation).
// Dapat di-test di environment manapun.
//
// Kriptografi: AES-256-GCM + PBKDF2-HMAC-SHA256 via pointycastle.
// Zero-failure policy: setiap error WAJIB dikonversi ke NodiraCryptoException.
//
// PERFORMA (2026-07-20):
//   • Seluruh pipeline (PBKDF2 + AES-GCM + base64 + utf8) berjalan dalam SATU
//     compute() — payload besar tidak lagi memblokir main isolate (dulu hanya
//     KDF yang di-isolate; GCM + base64 jalan di UI thread).
//   • Cache kunci turunan per-sesi: PBKDF2 200k iterasi (~0.8–2 dtk di Android
//     mid-range) hanya dihitung SEKALI per password per sesi app. Enkripsi
//     berikutnya dengan password sama (auto-backup tiap transaksi, recovery
//     blob PIN yang ikut tiap backup) memakai ulang salt + kunci ter-cache.
//     Aman: salt tetap tercatat di tiap envelope (file self-contained), IV
//     SELALU baru per enkripsi — reuse kunci AES-GCM dengan IV acak unik
//     berada jauh di bawah batas NIST SP 800-38D (2^32 pesan per kunci).
//     Trade-off: kunci turunan tinggal di RAM selama sesi — dibersihkan via
//     [NodiraCryptoEngine.clearKeyCache] saat factory reset.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'isolate_compute.dart';
import 'package:pointycastle/export.dart';

// ─────────────────────────────────────────────────────────────────────────────
// Exception
// ─────────────────────────────────────────────────────────────────────────────

class NodiraCryptoException implements Exception {
  const NodiraCryptoException({
    required this.code,
    required this.message,
    this.cause,
  });

  /// 'WRONG_PASSWORD' | 'CORRUPTED_FILE' | 'UNSUPPORTED_VERSION' | 'UNKNOWN'
  final String code;
  final String message;
  final Object? cause;

  @override
  String toString() => 'NodiraCryptoException[$code]: $message';
}

// ─────────────────────────────────────────────────────────────────────────────
// BackupEnvelope — representasi file .nodirabackup
// ─────────────────────────────────────────────────────────────────────────────

class BackupEnvelope {
  const BackupEnvelope({
    required this.version,
    required this.kdf,
    required this.iterations,
    required this.salt,
    required this.algorithm,
    required this.iv,
    required this.ciphertext,
    required this.authTag,
    required this.createdAt,
    required this.appVersion,
  });

  final int version;
  final String kdf;
  final int iterations;
  final String salt; // base64 — 16 bytes
  final String algorithm;
  final String iv; // base64 — 12 bytes
  final String ciphertext; // base64 — encrypted JSON
  final String authTag; // base64 — 16 bytes GCM tag
  final String createdAt; // ISO 8601
  final String appVersion;

  factory BackupEnvelope.fromJson(Map<String, dynamic> json) {
    try {
      return BackupEnvelope(
        version: json['version'] as int,
        kdf: json['kdf'] as String,
        iterations: json['iterations'] as int,
        salt: json['salt'] as String,
        algorithm: json['algorithm'] as String,
        iv: json['iv'] as String,
        ciphertext: json['ciphertext'] as String,
        authTag: json['authTag'] as String,
        createdAt: json['createdAt'] as String,
        appVersion: json['appVersion'] as String,
      );
    } catch (e) {
      throw NodiraCryptoException(
        code: 'CORRUPTED_FILE',
        message:
            'Format file backup tidak valid: field yang dibutuhkan tidak ditemukan',
        cause: e,
      );
    }
  }

  Map<String, dynamic> toJson() => {
        'version': version,
        'kdf': kdf,
        'iterations': iterations,
        'salt': salt,
        'algorithm': algorithm,
        'iv': iv,
        'ciphertext': ciphertext,
        'authTag': authTag,
        'createdAt': createdAt,
        'appVersion': appVersion,
      };

  BackupEnvelope copyWith({
    int? version,
    String? kdf,
    int? iterations,
    String? salt,
    String? algorithm,
    String? iv,
    String? ciphertext,
    String? authTag,
    String? createdAt,
    String? appVersion,
  }) {
    return BackupEnvelope(
      version: version ?? this.version,
      kdf: kdf ?? this.kdf,
      iterations: iterations ?? this.iterations,
      salt: salt ?? this.salt,
      algorithm: algorithm ?? this.algorithm,
      iv: iv ?? this.iv,
      ciphertext: ciphertext ?? this.ciphertext,
      authTag: authTag ?? this.authTag,
      createdAt: createdAt ?? this.createdAt,
      appVersion: appVersion ?? this.appVersion,
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level isolate workers — compute() hanya bisa memanggil top-level function.
// Error TIDAK dilempar lintas isolate (rapuh utk exception non-standar);
// worker mengembalikan map ber-tag {'ok': bool, ...} dan caller yang
// mengkonversi ke NodiraCryptoException (zero-failure policy tetap terjaga).
// ─────────────────────────────────────────────────────────────────────────────

Map<String, dynamic> _encryptWorker(Map<String, dynamic> args) {
  try {
    final cachedKey = args['key'] as Uint8List?;
    final password = args['password'] as String?;
    final salt = args['salt'] as Uint8List;
    final iv = args['iv'] as Uint8List;
    final iterations = args['iterations'] as int;
    final plaintext = args['plaintext'] as String;

    // KDF hanya bila kunci belum di-cache caller (miss pertama per sesi).
    final key =
        cachedKey ?? NodiraCryptoEngine.deriveKey(password!, salt, iterations);

    final raw = NodiraCryptoEngine._gcmProcess(
      encrypt: true,
      key: key,
      iv: iv,
      input: Uint8List.fromList(utf8.encode(plaintext)),
    );

    // pointycastle GCM output = ciphertext || authTag (16 byte terakhir).
    final ctLen = raw.length - NodiraCryptoEngine._tagSizeBytes;
    return {
      'ok': true,
      'key': key,
      'ct': base64.encode(raw.sublist(0, ctLen)),
      'tag': base64.encode(raw.sublist(ctLen)),
    };
  } catch (e) {
    return {'ok': false, 'code': 'UNKNOWN', 'msg': '$e'};
  }
}

Map<String, dynamic> _decryptWorker(Map<String, dynamic> args) {
  try {
    final cachedKey = args['key'] as Uint8List?;
    final password = args['password'] as String?;
    final salt = args['salt'] as Uint8List;
    final iv = args['iv'] as Uint8List;
    final iterations = args['iterations'] as int;

    // Base64 payload besar di-decode DI SINI (bukan di main isolate).
    final Uint8List ciphertext;
    final Uint8List authTag;
    try {
      ciphertext = base64.decode(args['ciphertext'] as String);
      authTag = base64.decode(args['authTag'] as String);
    } catch (e) {
      return {
        'ok': false,
        'code': 'CORRUPTED_FILE',
        'msg': 'File backup rusak: encoding base64 tidak valid',
      };
    }

    final key =
        cachedKey ?? NodiraCryptoEngine.deriveKey(password!, salt, iterations);

    // Gabungkan ciphertext + authTag (format pointycastle GCM decrypt).
    final combined = Uint8List(ciphertext.length + authTag.length);
    combined.setAll(0, ciphertext);
    combined.setAll(ciphertext.length, authTag);

    final Uint8List plain;
    try {
      plain = NodiraCryptoEngine._gcmProcess(
        encrypt: false,
        key: key,
        iv: iv,
        input: combined,
      );
    } on InvalidCipherTextException {
      // Auth tag gagal → password salah / file dimodifikasi.
      return {
        'ok': false,
        'code': 'WRONG_PASSWORD',
        'msg': 'Password salah atau file telah dimodifikasi',
      };
    }

    return {'ok': true, 'key': key, 'plaintext': utf8.decode(plain)};
  } catch (e) {
    return {'ok': false, 'code': 'UNKNOWN', 'msg': '$e'};
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// NodiraCryptoEngine
// ─────────────────────────────────────────────────────────────────────────────

class NodiraCryptoEngine {
  static const int _supportedVersion = 1;
  static const int _tagSizeBits = 128; // 16 bytes
  static const int _tagSizeBytes = 16;
  static const int _ivBytes = 12;
  static const int _saltBytes = 16;
  static const int _keyBytes = 32;
  static const int _iterations = 200000;

  // ── Cache kunci turunan per-sesi ──────────────────────────────────────────
  // Satu entri per arah (bukan map) — tidak menumpuk kunci di memori.
  // Encrypt: (password) → (salt, key); salt di-reuse dalam sesi supaya kunci
  // ter-cache tetap valid (lihat rationale keamanan di header file).
  // Decrypt: (password|saltB64|iterations) → key; membantu reveal PIN
  // berulang / restore file yang sama dua kali.
  static String? _encPwd;
  static Uint8List? _encSalt;
  static Uint8List? _encKey;
  static String? _decId;
  static Uint8List? _decKey;

  /// Bersihkan kunci ter-cache dari memori (panggil saat factory reset).
  static void clearKeyCache() {
    _encKey?.fillRange(0, _encKey!.length, 0);
    _decKey?.fillRange(0, _decKey!.length, 0);
    _encPwd = null;
    _encSalt = null;
    _encKey = null;
    _decId = null;
    _decKey = null;
  }

  // ── Encrypt ──────────────────────────────────────────────────────────────

  /// Mengenkripsi [plaintext] JSON string dengan [password].
  /// Returns: [BackupEnvelope] siap disimpan ke file.
  /// Throws: [NodiraCryptoException] jika ada error.
  Future<BackupEnvelope> encrypt(
    String plaintext,
    String password, {
    String appVersion = '1.0.0',
  }) async {
    // Cache hit → reuse salt+key sesi (KDF dilewati di worker); miss → salt
    // acak baru & worker menurunkan kunci. IV SELALU acak baru per enkripsi.
    final hit = _encPwd == password && _encKey != null && _encSalt != null;
    final salt = hit ? _encSalt! : _randomBytes(_saltBytes);
    final iv = _randomBytes(_ivBytes);

    final res = await compute<Map<String, dynamic>, Map<String, dynamic>>(
      _encryptWorker,
      {
        'key': hit ? _encKey : null,
        'password': hit ? null : password,
        'salt': salt,
        'iv': iv,
        'iterations': _iterations,
        'plaintext': plaintext,
      },
    );
    if (res['ok'] != true) {
      throw NodiraCryptoException(
        code: res['code'] as String? ?? 'UNKNOWN',
        message: res['msg'] as String? ?? 'Enkripsi gagal',
      );
    }

    // Simpan kunci utk enkripsi & dekripsi berikutnya dalam sesi ini.
    final key = res['key'] as Uint8List;
    _encPwd = password;
    _encSalt = salt;
    _encKey = key;
    _decId = '$password|${base64.encode(salt)}|$_iterations';
    _decKey = key;

    return BackupEnvelope(
      version: _supportedVersion,
      kdf: 'PBKDF2',
      iterations: _iterations,
      salt: base64.encode(salt),
      algorithm: 'AES-256-GCM',
      iv: base64.encode(iv),
      ciphertext: res['ct'] as String,
      authTag: res['tag'] as String,
      createdAt: DateTime.now().toUtc().toIso8601String(),
      appVersion: appVersion,
    );
  }

  // ── Decrypt ──────────────────────────────────────────────────────────────

  /// Mendekripsi [envelope] dengan [password].
  /// Returns: String JSON asli.
  /// Throws: [NodiraCryptoException] dengan kode:
  ///   - 'WRONG_PASSWORD'        — auth tag gagal / password salah
  ///   - 'CORRUPTED_FILE'        — format tidak valid
  ///   - 'UNSUPPORTED_VERSION'   — version > yang didukung
  Future<String> decrypt(BackupEnvelope envelope, String password) async {
    // 1. Validasi version
    if (envelope.version > _supportedVersion) {
      throw NodiraCryptoException(
        code: 'UNSUPPORTED_VERSION',
        message: 'Versi backup ${envelope.version} tidak didukung. '
            'Perbarui aplikasi ke versi terbaru.',
      );
    }

    // 2. Decode field kecil (salt+IV) di sini — dibutuhkan utk cek cache;
    //    ciphertext/authTag (besar) di-decode di worker.
    final Uint8List salt;
    final Uint8List iv;
    try {
      salt = base64.decode(envelope.salt);
      iv = base64.decode(envelope.iv);
    } catch (e) {
      throw NodiraCryptoException(
        code: 'CORRUPTED_FILE',
        message: 'File backup rusak: encoding base64 tidak valid',
        cause: e,
      );
    }

    final cacheId = '$password|${envelope.salt}|${envelope.iterations}';
    final hit = _decId == cacheId && _decKey != null;

    final res = await compute<Map<String, dynamic>, Map<String, dynamic>>(
      _decryptWorker,
      {
        'key': hit ? _decKey : null,
        'password': hit ? null : password,
        'salt': salt,
        'iv': iv,
        'iterations': envelope.iterations,
        'ciphertext': envelope.ciphertext,
        'authTag': envelope.authTag,
      },
    );
    if (res['ok'] != true) {
      throw NodiraCryptoException(
        code: res['code'] as String? ?? 'UNKNOWN',
        message: res['msg'] as String? ?? 'Dekripsi gagal',
      );
    }

    // Kunci terbukti benar (auth tag lolos) → cache utk dekripsi berikutnya,
    // dan seed cache enkripsi bila iterasi cocok (mis. backup setelah restore
    // dgn password sama tak perlu KDF lagi).
    final key = res['key'] as Uint8List;
    _decId = cacheId;
    _decKey = key;
    if (envelope.iterations == _iterations) {
      _encPwd = password;
      _encSalt = salt;
      _encKey = key;
    }

    return res['plaintext'] as String;
  }

  // ── deriveKey (synchronous — panggil via compute()) ───────────────────────

  /// Derive 256-bit key dari [password] + [salt] menggunakan PBKDF2-HMAC-SHA256.
  /// SYNCHRONOUS dan CPU-intensive — SELALU panggil via compute().
  static Uint8List deriveKey(
    String password,
    Uint8List salt,
    int iterations,
  ) {
    final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64));
    pbkdf2.init(Pbkdf2Parameters(salt, iterations, _keyBytes));
    return pbkdf2.process(Uint8List.fromList(utf8.encode(password)));
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  /// Jalankan AES-256-GCM encrypt atau decrypt.
  static Uint8List _gcmProcess({
    required bool encrypt,
    required Uint8List key,
    required Uint8List iv,
    required Uint8List input,
  }) {
    final cipher = GCMBlockCipher(AESEngine());
    cipher.init(
      encrypt,
      AEADParameters(
        KeyParameter(key),
        _tagSizeBits, // tag size dalam BITS
        iv,
        Uint8List(0), // additional data kosong
      ),
    );
    return cipher.process(input);
  }

  /// Generate [count] bytes cryptographically random.
  /// Random.secure() = CSPRNG OS — implementasi lama membungkusnya dengan
  /// FortunaRandom yang di-seed dari sumber yang sama (overhead tanpa nilai
  /// tambah keamanan).
  static Uint8List _randomBytes(int count) {
    final rng = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(count, (_) => rng.nextInt(256)),
    );
  }
}
