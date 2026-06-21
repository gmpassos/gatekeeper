import 'dart:typed_data';

/// Normalizes an IP [address] string so all layers agree on its family.
///
/// - Trims surrounding whitespace.
/// - Converts an IPv4-mapped IPv6 address (`::ffff:1.2.3.4`) to its plain
///   IPv4 form (`1.2.3.4`), since the kernel filters such traffic through the
///   IPv4 stack (`iptables`), not `ip6tables`.
///
/// Any other value (plain IPv4 or IPv6) is returned trimmed and unchanged.
String normalizeIpAddress(String address) {
  address = address.trim();

  // IPv4-mapped IPv6: `::ffff:1.2.3.4` (the IPv4 part is in dotted-quad form).
  var match = RegExp(r'^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$',
          caseSensitive: false)
      .firstMatch(address);
  if (match != null) {
    return match.group(1)!;
  }

  return address;
}

/// Returns `true` if [address] is an IPv6 address.
///
/// Expects an already [normalizeIpAddress]-normalized value, so IPv4-mapped
/// addresses (handled there) are treated as IPv4.
bool isIPv6Address(String address) {
  address = address.trim();
  // IPv4 addresses never contain `:`; IPv6 always does.
  return address.contains(':');
}

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
