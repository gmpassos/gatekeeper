import 'package:gatekeeper/gatekeeper.dart';
import 'package:gatekeeper/src/gatekeeper_mock.dart';
import 'package:gatekeeper/src/utils.dart';
import 'package:test/test.dart';

void main() {
  group('normalizeIpAddress', () {
    test('IPv4-mapped IPv6 -> IPv4', () {
      expect(normalizeIpAddress('::ffff:1.2.3.4'), equals('1.2.3.4'));
      expect(normalizeIpAddress('::FFFF:10.0.0.1'), equals('10.0.0.1'));
    });

    test('plain IPv4 unchanged', () {
      expect(normalizeIpAddress('192.168.0.1'), equals('192.168.0.1'));
    });

    test('plain IPv6 unchanged', () {
      expect(normalizeIpAddress('2001:db8::1'), equals('2001:db8::1'));
      expect(normalizeIpAddress('::1'), equals('::1'));
    });

    test('trims whitespace', () {
      expect(normalizeIpAddress('  1.2.3.4  '), equals('1.2.3.4'));
    });
  });

  group('isIPv6Address', () {
    test('IPv6', () {
      expect(isIPv6Address('2001:db8::1'), isTrue);
      expect(isIPv6Address('::1'), isTrue);
    });

    test('IPv4', () {
      expect(isIPv6Address('1.2.3.4'), isFalse);
    });

    test('IPv4-mapped (already normalized) treated as IPv4', () {
      expect(isIPv6Address(normalizeIpAddress('::ffff:1.2.3.4')), isFalse);
    });
  });

  group('Gatekeeper accept (family-agnostic via mock)', () {
    test('accept and list IPv4 and IPv6 addresses', () async {
      var gatekeeper =
          Gatekeeper(driver: GatekeeperMock(), allowAllPorts: true);

      expect(await gatekeeper.listAcceptedAddressesOnTCPPorts(),
          equals(<({String address, int port})>{}));

      expect(await gatekeeper.acceptAddressOnTCPPort('1.2.3.4', 22), isTrue);
      expect(
          await gatekeeper.acceptAddressOnTCPPort('2001:db8::1', 22), isTrue);

      expect(
          await gatekeeper.listAcceptedAddressesOnTCPPorts(),
          equals({
            (address: '1.2.3.4', port: 22),
            (address: '2001:db8::1', port: 22),
          }));

      expect(
          await gatekeeper.unacceptAddressOnTCPPort('2001:db8::1', 22), isTrue);
      expect(await gatekeeper.listAcceptedAddressesOnTCPPorts(),
          equals({(address: '1.2.3.4', port: 22)}));
    });
  });
}
