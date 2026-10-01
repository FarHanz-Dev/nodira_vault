// Minimal replacement for Flutter's `compute()` so the package is pure Dart.
//
// Runs [callback] with [message] in a short-lived isolate and returns the
// result. Same contract as Flutter's version for our usage: [callback] must be
// a top-level (or static) function and [message]/result must be sendable.
import 'dart:isolate';

Future<R> compute<M, R>(R Function(M message) callback, M message) =>
    Isolate.run<R>(() => callback(message));

/// Byte-wise list equality (replacement for Flutter's `listEquals`).
bool listEquals<T>(List<T>? a, List<T>? b) {
  if (identical(a, b)) return true;
  if (a == null || b == null || a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
