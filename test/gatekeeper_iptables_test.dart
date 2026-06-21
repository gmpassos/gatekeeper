import 'package:gatekeeper/gatekeeper_iptables.dart';
import 'package:test/test.dart';

void main() {
  group('GatekeeperIpTables validation', () {
    // These exercise the argument validation that runs *before* any
    // `iptables`/`ip6tables` binary is resolved, so they do not require the
    // firewall tools to be installed.
    final driver = GatekeeperIpTables();

    test('acceptAddressOnTCPPort: invalid port throws', () {
      expect(
        () => driver.acceptAddressOnTCPPort('1.2.3.4', 5,
            allowedPorts: null, allowAllPorts: true),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('acceptAddressOnTCPPort: invalid address throws', () {
      expect(
        () => driver.acceptAddressOnTCPPort('not an ip!', 22,
            allowedPorts: null, allowAllPorts: true),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('acceptAddressOnTCPPort: address with ".." throws', () {
      expect(
        () => driver.acceptAddressOnTCPPort('1.2..3.4', 22,
            allowedPorts: null, allowAllPorts: true),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('acceptAddressOnTCPPort: IPv6 address passes validation', () async {
      // Valid IPv6 + a disallowed port returns `false` *before* resolving
      // `ip6tables`, proving the address itself passed validation.
      var ok = await driver.acceptAddressOnTCPPort('2001:db8::1', 22,
          allowedPorts: {99}, allowAllPorts: false);
      expect(ok, isFalse);
    });

    test('acceptAddressOnTCPPort: disallowed port returns false', () async {
      var ok = await driver.acceptAddressOnTCPPort('1.2.3.4', 22,
          allowedPorts: {99}, allowAllPorts: false);
      expect(ok, isFalse);
    });

    test('blockTCPPort: invalid port throws', () {
      expect(
        () => driver.blockTCPPort(5, allowedPorts: null, allowAllPorts: true),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('blockTCPPort: disallowed port returns false', () async {
      var ok = await driver.blockTCPPort(22,
          allowedPorts: {99}, allowAllPorts: false);
      expect(ok, isFalse);
    });

    test('unblockTCPPort: invalid port throws', () {
      expect(
        () => driver.unblockTCPPort(5, allowedPorts: null, allowAllPorts: true),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}
