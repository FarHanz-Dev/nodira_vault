// lib/src/argon2id.dart
//
// Argon2id (RFC 9106, versi 0x13) dengan aritmetika `int` 64-bit NATIVE.
//
// ## Kenapa bukan `Argon2BytesGenerator` pointycastle lagi
//
// Laporan user 2026-09-28: *"mengapa proses buka vault lama sekali"*. Versi
// pointycastle ditulis supaya jalan juga di web, jadi tiap angka 64-bit di
// fungsi kompresinya adalah OBJEK `Register64` — satu blok 1 KiB berisi 128
// objek, dan Argon2id 64 MiB × 3 putaran mengompresi ±196 ribu blok. Di HP
// itu berdetik-detik, tepat di layar yang user tunggu sambil menatapnya.
//
// Nodira hanya jalan di VM/AOT, tempat `int` SUDAH 64-bit dua-komplemen dan
// penjumlahan/perkalian membungkus modulo 2^64 — persis aritmetika yang
// dituntut BlaMka. Pergeseran tanpa tanda memakai `>>>`. Jadi seluruh blok
// cukup satu `Uint64List`, tanpa satu alokasi pun di dalam loop.
//
// **Hasilnya WAJIB identik byte per byte dengan pointycastle**: vault yang
// sudah dibuat dibuka dengan parameter yang tertulis di keyring-nya, dan satu
// bit berbeda berarti passphrase yang benar ditolak sebagai salah. Dijaga
// `test/argon2id_native_test.dart` (dibandingkan langsung dengan pointycastle
// pada beberapa kombinasi parameter + vektor uji RFC 9106).
//
// Yang TIDAK didukung, dan memang tak dipakai vault: secret key (K),
// associated data (X), Argon2d/Argon2i murni, dan versi 0x10.
//
// Blake2b-nya (H0, H', tag akhir) tetap dari pointycastle — dipanggil hanya
// puluhan kali per derivasi, jadi tak ada yang perlu dipercepat di sana.

import 'dart:typed_data';

import 'package:pointycastle/digests/blake2b.dart';

const int _kBlockWords = 128; // 1 KiB = 128 × u64
const int _kSyncPoints = 4;
const int _kAddressesInBlock = 128;
const int _kVersion = 0x13;
const int _kTypeId = 2; // Argon2id
const int _kLow32 = 0xFFFFFFFF;

/// Argon2id([password], [salt]) → [length] byte.
///
/// [memoryKiB] = jumlah blok 1 KiB, [iterations] = t, [lanes] = p.
Uint8List argon2id({
  required Uint8List password,
  required Uint8List salt,
  required int memoryKiB,
  required int iterations,
  required int lanes,
  int length = 32,
}) {
  if (lanes < 1) throw ArgumentError.value(lanes, 'lanes');
  if (iterations < 1) throw ArgumentError.value(iterations, 'iterations');
  // m' = 4·p·⌊m / 4p⌋, minimal 8·p.
  var m = memoryKiB;
  if (m < 2 * _kSyncPoints * lanes) m = 2 * _kSyncPoints * lanes;
  final segmentLength = m ~/ (lanes * _kSyncPoints);
  final laneLength = segmentLength * _kSyncPoints;
  final blockCount = laneLength * lanes;

  // ── H0 ────────────────────────────────────────────────────────────────
  final h0In = BytesBuilder(copy: false)
    ..add(_le32(lanes))
    ..add(_le32(length))
    ..add(_le32(memoryKiB))
    ..add(_le32(iterations))
    ..add(_le32(_kVersion))
    ..add(_le32(_kTypeId))
    ..add(_le32(password.length))
    ..add(password)
    ..add(_le32(salt.length))
    ..add(salt)
    ..add(_le32(0)) // secret
    ..add(_le32(0)); // associated data
  final h0 = _blake2b(h0In.toBytes(), 64);

  final mem = Uint64List(blockCount * _kBlockWords);

  // ── Dua blok pertama tiap lane ────────────────────────────────────────
  final seed = Uint8List(64 + 8)..setRange(0, 64, h0);
  final seedView = ByteData.sublistView(seed);
  for (var l = 0; l < lanes; l++) {
    for (var j = 0; j < 2; j++) {
      seedView.setUint32(64, j, Endian.little);
      seedView.setUint32(68, l, Endian.little);
      final block = _hPrime(seed, 1024);
      _loadBlock(mem, (l * laneLength + j) * _kBlockWords, block);
    }
  }

  // ── Isi memori ────────────────────────────────────────────────────────
  final r = Uint64List(_kBlockWords);
  final q = Uint64List(_kBlockWords);
  final zero = Uint64List(_kBlockWords);
  final input = Uint64List(_kBlockWords);
  final address = Uint64List(_kBlockWords);

  for (var pass = 0; pass < iterations; pass++) {
    for (var slice = 0; slice < _kSyncPoints; slice++) {
      for (var lane = 0; lane < lanes; lane++) {
        final dataIndependent = pass == 0 && slice < _kSyncPoints ~/ 2;
        var startIndex = 0;
        if (dataIndependent) {
          input.fillRange(0, _kBlockWords, 0);
          input[0] = pass;
          input[1] = lane;
          input[2] = slice;
          input[3] = blockCount;
          input[4] = iterations;
          input[5] = _kTypeId;
        }
        if (pass == 0 && slice == 0) {
          startIndex = 2;
          if (dataIndependent) {
            _nextAddresses(input, address, zero, r, q);
          }
        }

        var curr = lane * laneLength + slice * segmentLength + startIndex;
        var prev = (curr % laneLength == 0) ? curr + laneLength - 1 : curr - 1;

        for (var i = startIndex; i < segmentLength; i++, curr++, prev++) {
          if (curr % laneLength == 1) prev = curr - 1;

          final int pseudoRand;
          if (dataIndependent) {
            if (i % _kAddressesInBlock == 0) {
              _nextAddresses(input, address, zero, r, q);
            }
            pseudoRand = address[i % _kAddressesInBlock];
          } else {
            pseudoRand = mem[prev * _kBlockWords];
          }

          var refLane = (pseudoRand >>> 32) % lanes;
          if (pass == 0 && slice == 0) refLane = lane;

          final refIndex = _indexAlpha(
            pass: pass,
            slice: slice,
            index: i,
            pseudoRand: pseudoRand & _kLow32,
            sameLane: refLane == lane,
            segmentLength: segmentLength,
            laneLength: laneLength,
          );

          _fillBlock(
            mem,
            prev * _kBlockWords,
            (refLane * laneLength + refIndex) * _kBlockWords,
            curr * _kBlockWords,
            withXor: pass != 0,
            r: r,
            q: q,
          );
        }
      }
    }
  }

  // ── Tag: XOR blok terakhir tiap lane, lalu H' ─────────────────────────
  final fin = Uint64List(_kBlockWords);
  for (var l = 0; l < lanes; l++) {
    final off = (l * laneLength + laneLength - 1) * _kBlockWords;
    for (var w = 0; w < _kBlockWords; w++) {
      fin[w] ^= mem[off + w];
    }
  }
  final finBytes = Uint8List(1024);
  final finView = ByteData.sublistView(finBytes);
  for (var w = 0; w < _kBlockWords; w++) {
    finView.setInt64(w * 8, fin[w], Endian.little);
  }
  return _hPrime(finBytes, length);
}

int _indexAlpha({
  required int pass,
  required int slice,
  required int index,
  required int pseudoRand,
  required bool sameLane,
  required int segmentLength,
  required int laneLength,
}) {
  int area;
  if (pass == 0) {
    if (slice == 0) {
      area = index - 1;
    } else if (sameLane) {
      area = slice * segmentLength + index - 1;
    } else {
      area = slice * segmentLength + (index == 0 ? -1 : 0);
    }
  } else {
    if (sameLane) {
      area = laneLength - segmentLength + index - 1;
    } else {
      area = laneLength - segmentLength + (index == 0 ? -1 : 0);
    }
  }
  // Perkalian dua bilangan < 2^32 muat di 64 bit TANPA tanda; `>>>` membacanya
  // sebagai tak bertanda walau `int` Dart menyimpannya sebagai negatif.
  var rel = (pseudoRand * pseudoRand) >>> 32;
  rel = area - 1 - ((area * rel) >>> 32);
  final start = pass == 0
      ? 0
      : (slice == _kSyncPoints - 1 ? 0 : (slice + 1) * segmentLength);
  return (start + rel) % laneLength;
}

/// Blok alamat berikutnya untuk pengalamatan data-independen:
/// address = G(0, G(0, input)), dengan penghitung `input[6]` dinaikkan dulu.
void _nextAddresses(Uint64List input, Uint64List address, Uint64List zero,
    Uint64List r, Uint64List q) {
  input[6] = input[6] + 1;
  _compress(zero, 0, input, 0, address, 0, false, r, q);
  _compress(zero, 0, address, 0, address, 0, false, r, q);
}

void _fillBlock(Uint64List mem, int prevOff, int refOff, int nextOff,
    {required bool withXor, required Uint64List r, required Uint64List q}) {
  _compress(mem, prevOff, mem, refOff, mem, nextOff, withXor, r, q);
}

/// next (^)= P(prev ⊕ ref) ⊕ (prev ⊕ ref).
void _compress(Uint64List prev, int prevOff, Uint64List ref, int refOff,
    Uint64List next, int nextOff, bool withXor, Uint64List r, Uint64List q) {
  for (var w = 0; w < _kBlockWords; w++) {
    final v = prev[prevOff + w] ^ ref[refOff + w];
    r[w] = v;
    q[w] = v;
  }
  // Baris.
  for (var i = 0; i < 8; i++) {
    final b = 16 * i;
    _round(q, b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7, b + 8, b + 9,
        b + 10, b + 11, b + 12, b + 13, b + 14, b + 15);
  }
  // Kolom.
  for (var i = 0; i < 8; i++) {
    final b = 2 * i;
    _round(q, b, b + 1, b + 16, b + 17, b + 32, b + 33, b + 48, b + 49, b + 64,
        b + 65, b + 80, b + 81, b + 96, b + 97, b + 112, b + 113);
  }
  if (withXor) {
    for (var w = 0; w < _kBlockWords; w++) {
      next[nextOff + w] ^= q[w] ^ r[w];
    }
  } else {
    for (var w = 0; w < _kBlockWords; w++) {
      next[nextOff + w] = q[w] ^ r[w];
    }
  }
}

@pragma('vm:prefer-inline')
void _round(
    Uint64List v,
    int v0,
    int v1,
    int v2,
    int v3,
    int v4,
    int v5,
    int v6,
    int v7,
    int v8,
    int v9,
    int v10,
    int v11,
    int v12,
    int v13,
    int v14,
    int v15) {
  _g(v, v0, v4, v8, v12);
  _g(v, v1, v5, v9, v13);
  _g(v, v2, v6, v10, v14);
  _g(v, v3, v7, v11, v15);
  _g(v, v0, v5, v10, v15);
  _g(v, v1, v6, v11, v12);
  _g(v, v2, v7, v8, v13);
  _g(v, v3, v4, v9, v14);
}

@pragma('vm:prefer-inline')
void _g(Uint64List v, int ia, int ib, int ic, int id) {
  var a = v[ia], b = v[ib], c = v[ic], d = v[id];
  a = a + b + 2 * (a & _kLow32) * (b & _kLow32);
  d = _rotr(d ^ a, 32);
  c = c + d + 2 * (c & _kLow32) * (d & _kLow32);
  b = _rotr(b ^ c, 24);
  a = a + b + 2 * (a & _kLow32) * (b & _kLow32);
  d = _rotr(d ^ a, 16);
  c = c + d + 2 * (c & _kLow32) * (d & _kLow32);
  b = _rotr(b ^ c, 63);
  v[ia] = a;
  v[ib] = b;
  v[ic] = c;
  v[id] = d;
}

@pragma('vm:prefer-inline')
int _rotr(int x, int n) => (x >>> n) | (x << (64 - n));

void _loadBlock(Uint64List mem, int off, Uint8List bytes) {
  final view = ByteData.sublistView(bytes);
  for (var w = 0; w < _kBlockWords; w++) {
    mem[off + w] = view.getInt64(w * 8, Endian.little);
  }
}

/// H' — hash panjang-variabel Argon2.
Uint8List _hPrime(Uint8List x, int outLen) {
  final prefixed = Uint8List(4 + x.length)
    ..setRange(0, 4, _le32(outLen))
    ..setRange(4, 4 + x.length, x);
  if (outLen <= 64) return _blake2b(prefixed, outLen);
  final out = Uint8List(outLen);
  final r = (outLen + 31) ~/ 32 - 2;
  var v = _blake2b(prefixed, 64);
  out.setRange(0, 32, v);
  var pos = 32;
  for (var i = 1; i < r; i++) {
    v = _blake2b(v, 64);
    out.setRange(pos, pos + 32, v);
    pos += 32;
  }
  final last = _blake2b(v, outLen - 32 * r);
  out.setRange(pos, outLen, last);
  return out;
}

Uint8List _blake2b(Uint8List input, int outLen) {
  final d = Blake2bDigest(digestSize: outLen);
  d.update(input, 0, input.length);
  final out = Uint8List(outLen);
  d.doFinal(out, 0);
  return out;
}

Uint8List _le32(int v) =>
    Uint8List(4)..buffer.asByteData().setUint32(0, v, Endian.little);
