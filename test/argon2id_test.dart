// Argon2id native (`lib/core/byos/argon2id.dart`) WAJIB identik byte per byte
// dengan pointycastle, implementasi yang dipakai membuat vault sampai
// 2026-09-28: vault lama dibuka dengan parameter yang tertulis di keyring-nya,
// dan satu bit berbeda berarti passphrase yang benar ditolak sebagai salah.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:nodira_vault/src/argon2id.dart';
import 'package:pointycastle/export.dart';

Uint8List _pc({
  required Uint8List pwd,
  required Uint8List salt,
  required int m,
  required int t,
  required int p,
  int len = 32,
}) {
  final params = Argon2Parameters(
    Argon2Parameters.ARGON2_id,
    salt,
    desiredKeyLength: len,
    iterations: t,
    memory: m,
    lanes: p,
    version: Argon2Parameters.ARGON2_VERSION_13,
  );
  return (Argon2BytesGenerator()..init(params)).process(pwd);
}

Uint8List _b(String s) => Uint8List.fromList(utf8.encode(s));

String _hex(List<int> b) =>
    b.map((e) => e.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('identik dengan pointycastle', () {
    final salt = Uint8List.fromList(List.generate(16, (i) => i * 7 + 3));
    final cases = <(int m, int t, int p, int len)>[
      (8, 1, 1, 32), // di bawah minimum → dinaikkan ke 8·p
      (64, 1, 1, 32), // VaultKdfParams.testOnly
      (256, 2, 2, 32),
      (512, 3, 2, 32), // bentuk vault (t=3, p=2), memori diperkecil
      (1024, 3, 4, 32),
      (300, 2, 3, 64), // m bukan kelipatan 4p
      (2048, 1, 2, 16), // pengalamatan data-independen lintas >128 blok
    ];
    for (final (m, t, p, len) in cases) {
      test('m=$m t=$t p=$p len=$len', () {
        final pwd = _b('kata sandi vault — ünïcödé');
        final native = argon2id(
          password: pwd,
          salt: salt,
          memoryKiB: m,
          iterations: t,
          lanes: p,
          length: len,
        );
        expect(_hex(native),
            _hex(_pc(pwd: pwd, salt: salt, m: m, t: t, p: p, len: len)));
      });
    }

    test('parameter vault SUNGGUHAN (64 MiB, t=3, p=2)', () {
      final pwd = _b('passphrase');
      final s = Uint8List(16);
      final sw = Stopwatch()..start();
      final native = argon2id(
          password: pwd,
          salt: s,
          memoryKiB: 64 * 1024,
          iterations: 3,
          lanes: 2);
      final nativeMs = sw.elapsedMilliseconds;
      sw.reset();
      final pc = _pc(pwd: pwd, salt: s, m: 64 * 1024, t: 3, p: 2);
      final pcMs = sw.elapsedMilliseconds;
      expect(_hex(native), _hex(pc));
      // ignore: avoid_print
      print(
          'Argon2id 64 MiB t3 p2 — native $nativeMs ms, pointycastle $pcMs ms');
    });
  });

  test('vault_crypto memakai implementasi native', () {
    final src = File('lib/src/vault_crypto.dart').readAsStringSync();
    expect(src.contains('argon2id('), isTrue);
    expect(src.contains('Argon2BytesGenerator()'), isFalse,
        reason: 'pointycastle Argon2 memakai Register64 — detik-detikan di HP');
  });
}
