import 'package:gatekeeper/gatekeeper.dart';
import 'package:gatekeeper/src/gatekeeper_mock.dart';
import 'package:test/test.dart';

void main() {
  group('Gatekeeper', () {
    test('allowAllPorts: true', () async {
      var gatekeeper =
          Gatekeeper(driver: GatekeeperMock({}), allowAllPorts: true);

      expect(await gatekeeper.listBlockedTCPPorts(), equals(<int>{}));

      expect(await gatekeeper.blockTCPPort(2223), isTrue);
      expect(await gatekeeper.listBlockedTCPPorts(), equals({2223}));

      expect(await gatekeeper.blockTCPPort(2224), isTrue);
      expect(await gatekeeper.listBlockedTCPPorts(), equals({2223, 2224}));

      expect(await gatekeeper.unblockTCPPort(2223), isTrue);
      expect(await gatekeeper.listBlockedTCPPorts(), equals({2224}));

      expect(await gatekeeper.unblockTCPPort(2225), isTrue);
      expect(await gatekeeper.listBlockedTCPPorts(), equals({2224}));
    });

    test('allowAllPorts: false', () async {
      var gatekeeper =
          Gatekeeper(driver: GatekeeperMock({}), allowAllPorts: false);

      expect(await gatekeeper.listBlockedTCPPorts(), equals(<int>{}));

      expect(await gatekeeper.blockTCPPort(2223), isFalse);
      expect(await gatekeeper.listBlockedTCPPorts(), equals(<int>{}));

      expect(await gatekeeper.unblockTCPPort(2223), isFalse);
      expect(await gatekeeper.listBlockedTCPPorts(), equals(<int>{}));
    });

    test('allowAllPorts: false ; allowedPorts: {2223, 2224}', () async {
      var gatekeeper = Gatekeeper(
          driver: GatekeeperMock({}),
          allowAllPorts: false,
          allowedPorts: {2223, 2224});

      expect(await gatekeeper.listBlockedTCPPorts(), equals(<int>{}));

      expect(await gatekeeper.blockTCPPort(2223), isTrue);
      expect(await gatekeeper.listBlockedTCPPorts(), equals(<int>{2223}));

      expect(await gatekeeper.blockTCPPort(223), isFalse);
      expect(await gatekeeper.listBlockedTCPPorts(), equals(<int>{2223}));

      expect(await gatekeeper.blockTCPPort(2224), isTrue);
      expect(await gatekeeper.listBlockedTCPPorts(), equals(<int>{2223, 2224}));

      expect(await gatekeeper.blockTCPPort(2225), isFalse);
      expect(await gatekeeper.listBlockedTCPPorts(), equals(<int>{2223, 2224}));

      expect(await gatekeeper.unblockTCPPort(2223), isTrue);
      expect(await gatekeeper.listBlockedTCPPorts(), equals(<int>{2224}));

      expect(await gatekeeper.unblockTCPPort(2225), isFalse);
      expect(await gatekeeper.listBlockedTCPPorts(), equals(<int>{2224}));
    });
  });
}
