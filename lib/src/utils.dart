import 'dart:typed_data';

extension Uint8ListExtension on Uint8List {
  Uint8List merge(Uint8List other) {
    if (isEmpty) return other;
    if (other.isEmpty) return this;
    var bs = Uint8List(length + other.length);
    bs.setRange(0, length, this);
    bs.setRange(length, length + other.length, other);
    return bs;
  }
}
