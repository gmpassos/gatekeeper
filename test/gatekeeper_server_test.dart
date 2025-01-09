import 'package:gatekeeper/gatekeeper_client.dart';
import 'package:gatekeeper/gatekeeper_server.dart';
import 'package:gatekeeper/src/gatekeeper_mock.dart';
import 'package:test/test.dart';

const accessKey = '0123456789abcdefghijklmnopqrstuvwxyz';

void main() {
  group('GatekeeperServer', () {
    test('allowedPorts: {2223, 2224} ; GatekeeperClient', () async {
      final listenPort = 2243;

      final driver = GatekeeperMock({});

      final gatekeeperServer = GatekeeperServer(
          Gatekeeper(driver: driver, allowedPorts: {2223, 2224}),
          listenPort: listenPort,
          accessKey: accessKey);

      expect(await gatekeeperServer.start(), isTrue);

      expect(gatekeeperServer.isStarted, isTrue);

      {
        var clientNotLogged = GatekeeperClient('localhost', listenPort);

        expect(await clientNotLogged.connect(), isTrue);

        expect(await clientNotLogged.listBlockedTCPPorts(), equals(<int>{}));

        expect(
            () => clientNotLogged.blockTCPPort(2223),
            throwsA(isA<StateError>().having(
                (e) => e.message, 'message', contains('not connected'))));
      }

      var client = GatekeeperClient('localhost', listenPort);

      expect(await client.connect(), isTrue);

      expect(client.isConnected, isTrue);

      expect(await client.login(accessKey), isTrue);

      expect(await client.listBlockedTCPPorts(), equals(<int>{}));

      expect(await client.blockTCPPort(2223), isTrue);

      expect(await client.listBlockedTCPPorts(), equals(<int>{2223}));

      expect(await client.blockTCPPort(2224), isTrue);

      expect(await client.listBlockedTCPPorts(), equals(<int>{2223, 2224}));

      expect(await client.blockTCPPort(222), isFalse);
      expect(await client.listBlockedTCPPorts(), equals(<int>{2223, 2224}));

      expect(await client.unblockTCPPort(2223), isTrue);
      expect(await client.listBlockedTCPPorts(), equals(<int>{2224}));

      expect(await client.unblockTCPPort(2224), isTrue);
      expect(await client.listBlockedTCPPorts(), equals(<int>{}));

      client.close();
      expect(client.isConnected, isFalse);

      gatekeeperServer.close();
      expect(gatekeeperServer.isStarted, isFalse);
    });
  });
}
