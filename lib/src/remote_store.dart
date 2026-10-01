// lib/src/remote_store.dart
//
// Antarmuka penyimpanan jarak jauh BYOS (BYOS_SPEC.md §8). Sengaja MINIMAL
// dan tanpa `putIfAbsent`/compare-and-swap: Drive, SAF, dan WebDAV polos
// tak punya CAS, jadi desain vault disusun supaya tak pernah butuh — tiap
// perangkat menulis objeknya SENDIRI, dan objek bersama cuma keyring (ditulis
// sekali saat vault dibuat).
//
// Semua nama yang lewat sini sudah berupa hash (`VaultKeys.objectName`)
// kecuali `kKeyringName`. Penyimpanan tak pernah melihat nama bermakna.

import 'dart:typed_data';

/// Nama tetap objek keyring — satu-satunya yang harus bisa ditemukan sebelum
/// kunci apa pun ada. Isinya cuma MK terbungkus + parameter KDF.
const kKeyringName = 'nodira.keyring';

class RemoteEntry {
  const RemoteEntry({
    required this.name,
    required this.size,
    required this.modified,
  });

  final String name;
  final int size;
  final DateTime modified;
}

/// Kegagalan penyimpanan. Kodenya DISEBUT (aturan `UNKNOWN` haram,
/// `docs/auto-backup.md`) supaya kartu status bisa menyebut sebabnya.
class RemoteStoreException implements Exception {
  const RemoteStoreException(this.code, [this.detail = '']);

  /// `NOT_SIGNED_IN` · `PERMISSION_DENIED` · `QUOTA_EXCEEDED` · `NOT_FOUND`
  /// · `NETWORK` · `SERVER`
  final String code;
  final String detail;

  @override
  String toString() => 'RemoteStoreException($code): $detail';
}

abstract class RemoteStore {
  /// Seluruh objek di vault ini.
  Future<List<RemoteEntry>> list();

  /// Isi satu objek; `NOT_FOUND` bila tak ada.
  Future<Uint8List> get(String name);

  /// Tulis/timpa satu objek. WAJIB idempoten: unggahan yang gagal di tengah
  /// cukup diulang dengan nama yang sama.
  Future<void> put(String name, Uint8List bytes);

  Future<void> delete(String name);
}

/// Penyimpanan di memori — untuk test, dan sebagai acuan perilaku yang
/// harus ditiru backend sungguhan.
class MemoryRemoteStore implements RemoteStore {
  final Map<String, (Uint8List, DateTime)> _objects = {};

  /// Terlihat oleh test: nama apa saja yang pernah "diunggah".
  Iterable<String> get names => _objects.keys;

  @override
  Future<List<RemoteEntry>> list() async => [
        for (final e in _objects.entries)
          RemoteEntry(
              name: e.key, size: e.value.$1.length, modified: e.value.$2),
      ];

  @override
  Future<Uint8List> get(String name) async {
    final o = _objects[name];
    if (o == null) throw RemoteStoreException('NOT_FOUND', name);
    return Uint8List.fromList(o.$1);
  }

  @override
  Future<void> put(String name, Uint8List bytes) async {
    _objects[name] = (Uint8List.fromList(bytes), DateTime.now());
  }

  @override
  Future<void> delete(String name) async => _objects.remove(name);
}
