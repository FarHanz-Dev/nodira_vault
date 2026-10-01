// lib/src/vault_crypto.dart
//
// Kriptografi VAULT BYOS — fase 0 di BYOS_SPEC.md (§7). Terpisah dari
// `NodiraCryptoEngine` dengan sengaja: yang itu melindungi SATU berkas di
// perangkat user; yang ini melindungi seluruh riwayat yang duduk PERMANEN di
// server pihak ketiga (Google Drive), dan ancamannya berbeda.
//
// ## Kenapa Argon2id, bukan PBKDF2 yang sudah ada
//
// Begitu ciphertext ada di Drive, ia bisa disalin diam-diam lalu digempur
// offline dengan GPU tanpa batas waktu. PBKDF2 tidak memory-hard — persis
// beban kerja yang paling murah dipercepat GPU. Argon2id memaksa tiap tebakan
// membayar 64 MiB memori. Parameternya DISIMPAN di keyring, jadi menaikkannya
// kelak tak mematahkan vault lama.
//
// ## Hierarki kunci (§7.2)
//
//   passphrase --Argon2id(salt)--> KEK
//   MK (32 B acak, sekali per vault) --AES-GCM(KEK)--> keyring
//   MK --HKDF("name")-->            K_name  (HMAC nama objek)
//   MK --HKDF("obj:"+objectId)-->   K_obj   (satu kunci per objek)
//
// - Ganti passphrase = bungkus ulang MK saja, bukan enkripsi ulang vault.
// - SATU KUNCI PER OBJEK → IV boleh nol. Penggunaan ulang nonce di GCM itu
//   katastrofik; memberi tiap objek kunci sendiri menghapus seluruh kelas
//   kesalahan itu alih-alih menggantungkannya pada generator acak.
// - Nama objek = HMAC(K_name, jalur logis). Nama seperti
//   `snapshot-2026-09-25` membocorkan kapan user aktif kepada penyedia yang
//   seharusnya tak tahu apa-apa (§6.5 aturan 3).
//
// ## Yang TIDAK dijanjikan
//
// Lupa passphrase = vault jadi byte acak selamanya. Tak ada reset — kalau bisa
// direset, berarti kita bisa membacanya. Itu jaminannya, bukan kekurangannya.

import 'dart:convert';
import 'dart:io' show gzip;
import 'dart:math';
import 'dart:typed_data';

import 'isolate_compute.dart';
import 'package:pointycastle/export.dart';
import 'argon2id.dart';

/// Kegagalan vault. Kodenya kosakata yang sama dengan `classifyRestoreError`
/// supaya satu layar bisa menjelaskan keduanya (UNKNOWN tetap haram).
class VaultCryptoException implements Exception {
  const VaultCryptoException(this.code, [this.message = '']);

  /// `WRONG_PASSPHRASE` · `CORRUPTED_OBJECT` · `UNSUPPORTED_VERSION`
  final String code;
  final String message;

  @override
  String toString() => 'VaultCryptoException($code): $message';
}

/// Parameter Argon2id. Disimpan di keyring — pembuka vault memakai angka
/// yang TERTULIS di sana, bukan konstanta app, jadi menaikkan biaya kelak
/// tak mengunci vault lama.
class VaultKdfParams {
  const VaultKdfParams({
    this.memoryKiB = 64 * 1024, // 64 MiB (§7.1)
    this.iterations = 3,
    this.lanes = 2,
  });

  /// Hanya untuk test: Argon2id 64 MiB memakan detik per panggilan.
  const VaultKdfParams.testOnly()
      : memoryKiB = 64,
        iterations = 1,
        lanes = 1;

  final int memoryKiB;
  final int iterations;
  final int lanes;

  Map<String, dynamic> toJson() =>
      {'m': memoryKiB, 't': iterations, 'p': lanes};

  factory VaultKdfParams.fromJson(Map<String, dynamic> j) => VaultKdfParams(
        memoryKiB: (j['m'] as num).toInt(),
        iterations: (j['t'] as num).toInt(),
        lanes: (j['p'] as num).toInt(),
      );
}

/// Objek `keyring` di penyimpanan: MK yang dibungkus KEK. Satu-satunya objek
/// ber-NAMA TETAP — ia harus bisa ditemukan SEBELUM kunci apa pun ada. Isinya
/// tak membocorkan apa pun selain parameter KDF (yang memang harus publik).
class VaultKeyring {
  const VaultKeyring({
    required this.vaultId,
    required this.kdf,
    required this.salt,
    required this.wrappedMk,
    this.version = 1,
  });

  final int version;
  final String vaultId; // acak, tak bermakna; mengikat objek ke vault-nya
  final VaultKdfParams kdf;
  final Uint8List salt;
  final Uint8List wrappedMk; // AES-GCM(KEK, IV nol) atas MK — KEK unik per salt

  Uint8List toBytes() => Uint8List.fromList(utf8.encode(jsonEncode({
        'v': version,
        'id': vaultId,
        'kdf': kdf.toJson(),
        'salt': base64Encode(salt),
        'mk': base64Encode(wrappedMk),
      })));

  factory VaultKeyring.fromBytes(Uint8List bytes) {
    try {
      final j = jsonDecode(utf8.decode(bytes)) as Map<String, dynamic>;
      final v = (j['v'] as num).toInt();
      if (v != 1) {
        throw VaultCryptoException('UNSUPPORTED_VERSION', 'keyring v$v');
      }
      return VaultKeyring(
        version: v,
        vaultId: j['id'] as String,
        kdf: VaultKdfParams.fromJson(j['kdf'] as Map<String, dynamic>),
        salt: base64Decode(j['salt'] as String),
        wrappedMk: base64Decode(j['mk'] as String),
      );
    } on VaultCryptoException {
      rethrow;
    } catch (e) {
      throw VaultCryptoException('CORRUPTED_OBJECT', 'keyring: $e');
    }
  }
}

/// Kunci vault yang sudah terbuka. Hidup di memori selama sesi saja —
/// Argon2id 64 MiB tak boleh dijalankan tiap unggahan.
class VaultKeys {
  VaultKeys._(this.vaultId, this._mk) : _kName = _hkdf(_mk, 'name');

  final String vaultId;
  final Uint8List _mk;
  final Uint8List _kName;

  /// Bentuk yang disimpan di PERANGKAT ini untuk sinkron otomatis
  /// (`VaultKeyStore`, flutter_secure_storage — Keystore Android). Tak pernah
  /// dikirim ke mana pun: vault tetap hanya bisa dibuka di perangkat LAIN
  /// dengan passphrase.
  String toDeviceSecret() =>
      jsonEncode({'v': 1, 'id': vaultId, 'mk': base64Encode(_mk)});

  /// Kebalikan [toDeviceSecret]. Bentuk tak dikenal → null, bukan lemparan:
  /// satu nilai rusak di secure storage cuma mematikan sinkron otomatis.
  static VaultKeys? fromDeviceSecret(String raw) {
    try {
      final j = jsonDecode(raw) as Map<String, dynamic>;
      if (j['v'] != 1) return null;
      return VaultKeys._(j['id'] as String,
          Uint8List.fromList(base64Decode(j['mk'] as String)));
    } catch (_) {
      return null;
    }
  }

  /// Nama objek di penyimpanan untuk sebuah jalur LOGIS. Deterministik (dua
  /// perangkat menghitung nama yang sama), tak bisa dibalik tanpa MK.
  String objectName(String logicalPath) {
    final mac = HMac(SHA256Digest(), 64)..init(KeyParameter(_kName));
    final out = mac.process(Uint8List.fromList(utf8.encode(logicalPath)));
    return _hex(out.sublist(0, 16)); // 128 bit cukup untuk keunikan nama
  }

  /// Kemas plaintext jadi objek tersegel: gzip → AES-256-GCM dengan kunci
  /// milik objek ini sendiri. Format:
  ///
  ///   'NDV1' (4) | objectId (16) | ciphertext+tag
  ///
  /// Kompresi SEBELUM enkripsi — sesudahnya tak ada lagi yang bisa
  /// dikompres (§6.6).
  Uint8List seal(Uint8List plaintext, {Random? random}) {
    final rnd = random ?? Random.secure();
    final objectId =
        Uint8List.fromList(List.generate(16, (_) => rnd.nextInt(256)));
    final key = _hkdf(_mk, 'obj:${_hex(objectId)}');
    final header = Uint8List.fromList([..._kMagic, ...objectId]);
    final body = _gcm(true, key, Uint8List.fromList(gzip.encode(plaintext)),
        aad: header);
    return Uint8List.fromList([...header, ...body]);
  }

  /// Kebalikan [seal]. Objek yang dipotong, disunting, atau milik vault lain
  /// gagal di tag GCM → `CORRUPTED_OBJECT`, tak pernah plaintext palsu.
  Uint8List open(Uint8List sealed) {
    if (sealed.length < _kHeaderLen + 16 ||
        !listEquals(sealed.sublist(0, 4), _kMagic)) {
      throw const VaultCryptoException('CORRUPTED_OBJECT', 'header');
    }
    final header = sealed.sublist(0, _kHeaderLen);
    final objectId = sealed.sublist(4, _kHeaderLen);
    final key = _hkdf(_mk, 'obj:${_hex(objectId)}');
    try {
      final zipped = _gcm(false, key, sealed.sublist(_kHeaderLen), aad: header);
      return Uint8List.fromList(gzip.decode(zipped));
    } catch (_) {
      throw const VaultCryptoException('CORRUPTED_OBJECT', 'tag/gzip');
    }
  }
}

const _kMagic = [0x4E, 0x44, 0x56, 0x31]; // "NDV1"
const _kHeaderLen = 4 + 16;

/// Titik masuk vault. Argon2id berjalan di `compute()` — tak memblokir UI.
class VaultCrypto {
  VaultCrypto._();

  /// Buat vault baru: MK acak, dibungkus KEK dari [passphrase].
  static Future<(VaultKeyring, VaultKeys)> create(
    String passphrase, {
    VaultKdfParams kdf = const VaultKdfParams(),
    Random? random,
  }) async {
    final rnd = random ?? Random.secure();
    Uint8List bytes(int n) =>
        Uint8List.fromList(List.generate(n, (_) => rnd.nextInt(256)));
    final mk = bytes(32);
    final salt = bytes(16);
    final vaultId = _hex(bytes(16));
    final kek = await _deriveKek(passphrase, salt, kdf);
    final keyring = VaultKeyring(
      vaultId: vaultId,
      kdf: kdf,
      salt: salt,
      wrappedMk: _gcm(true, kek, mk, aad: utf8.encode(vaultId)),
    );
    return (keyring, VaultKeys._(vaultId, mk));
  }

  /// Buka vault. Passphrase salah gagal di tag GCM → `WRONG_PASSPHRASE`.
  static Future<VaultKeys> unlock(
      VaultKeyring keyring, String passphrase) async {
    final kek = await _deriveKek(passphrase, keyring.salt, keyring.kdf);
    try {
      final mk = _gcm(false, kek, keyring.wrappedMk,
          aad: utf8.encode(keyring.vaultId));
      return VaultKeys._(keyring.vaultId, mk);
    } catch (_) {
      throw const VaultCryptoException('WRONG_PASSPHRASE');
    }
  }

  /// Ganti passphrase: bungkus ulang MK dengan salt BARU. Isi vault tak
  /// disentuh sama sekali.
  static Future<VaultKeyring> rewrap(
    VaultKeyring keyring,
    VaultKeys keys,
    String newPassphrase, {
    Random? random,
  }) async {
    final rnd = random ?? Random.secure();
    final salt = Uint8List.fromList(List.generate(16, (_) => rnd.nextInt(256)));
    final kek = await _deriveKek(newPassphrase, salt, keyring.kdf);
    return VaultKeyring(
      vaultId: keyring.vaultId,
      kdf: keyring.kdf,
      salt: salt,
      wrappedMk: _gcm(true, kek, keys._mk, aad: utf8.encode(keyring.vaultId)),
    );
  }

  static Future<Uint8List> _deriveKek(
      String passphrase, Uint8List salt, VaultKdfParams kdf) {
    return compute(_argon2idIsolate, <String, Object>{
      'p': passphrase,
      's': salt,
      'm': kdf.memoryKiB,
      't': kdf.iterations,
      'l': kdf.lanes,
    });
  }
}

/// Top-level supaya bisa dikirim ke isolate.
///
/// Implementasi `int` 64-bit native (`argon2id.dart`), bukan
/// `Argon2BytesGenerator` pointycastle: hasilnya identik byte per byte, tapi
/// yang lama menghitung tiap angka 64-bit sebagai objek `Register64` dan
/// membuat "Buka vault" berdetik-detik di HP (laporan user 2026-09-28).
Uint8List _argon2idIsolate(Map<String, Object> a) => argon2id(
      password: Uint8List.fromList(utf8.encode(a['p'] as String)),
      salt: a['s'] as Uint8List,
      memoryKiB: a['m'] as int,
      iterations: a['t'] as int,
      lanes: a['l'] as int,
    );

Uint8List _hkdf(Uint8List ikm, String info) {
  final d = HKDFKeyDerivator(SHA256Digest())
    ..init(
        HkdfParameters(ikm, 32, null, Uint8List.fromList(utf8.encode(info))));
  return d.process(Uint8List(0));
}

/// AES-256-GCM, IV NOL. Aman HANYA karena tiap pemanggil memakai kunci yang
/// unik untuk satu plaintext (kunci per objek / KEK per salt). Jangan pernah
/// memanggilnya dengan kunci yang dipakai ulang.
Uint8List _gcm(bool encrypt, Uint8List key, Uint8List input,
    {required List<int> aad}) {
  final c = GCMBlockCipher(AESEngine())
    ..init(
      encrypt,
      AEADParameters(
          KeyParameter(key), 128, Uint8List(12), Uint8List.fromList(aad)),
    );
  return c.process(input);
}

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
