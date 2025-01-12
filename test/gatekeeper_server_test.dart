import 'package:gatekeeper/gatekeeper_client.dart';
import 'package:gatekeeper/gatekeeper_server.dart';
import 'package:test/test.dart';

const accessKey = '0123456789abcdefghijklmnopqrstuvwxyz';

void main() {
  group('GatekeeperServer', () {
    test('allowedPorts: {2223, 2224} ; GatekeeperClient',
        () => _testServer(secure: false));

    test('allowedPorts: {2223, 2224} ; GatekeeperClient (secure)',
        () => _testServer(secure: true));
  });
}

Future<void> _testServer({required bool secure}) async {
  final listenPort = 2243;

  final driver = GatekeeperMock(verbose: true);

  final gatekeeperServer = GatekeeperServer(
    Gatekeeper(driver: driver, allowedPorts: {2223, 2224}),
    listenPort: listenPort,
    accessKey: accessKey,
    verbose: true,
  );

  expect(await gatekeeperServer.start(), isTrue);

  expect(gatekeeperServer.isStarted, isTrue);

  {
    var clientNotLogged = GatekeeperClient('localhost', listenPort,
        secure: secure, verbose: true);

    expect(await clientNotLogged.connect(), isTrue);

    if (secure) {
      expect(
        () => clientNotLogged.listBlockedTCPPorts(),
        throwsA(isA<StateError>().having(
            (e) => e.message, 'message', contains('`_accessKey` not defined'))),
      );
    } else {
      expect(await clientNotLogged.listBlockedTCPPorts(), equals(<int>{}));
    }

    if (secure) {
      expect(
        () => clientNotLogged.blockTCPPort(2223),
        throwsA(isA<StateError>().having(
            (e) => e.message, 'message', contains('`_accessKey` not defined'))),
      );
    } else {
      expect(
        () => clientNotLogged.blockTCPPort(2223),
        throwsA(
          isA<StateError>()
              .having((e) => e.message, 'message', contains('not connected')),
        ),
      );
    }
  }

  var client =
      GatekeeperClient('localhost', listenPort, secure: secure, verbose: true);

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

  expect(await client.acceptAddressOnTCPPort('192.168.0.100', 2224), isTrue);

  expect(
      await client.listAcceptedAddressesOnTCPPorts(),
      equals(<({String address, int port})>{
        (address: '192.168.0.100', port: 2224),
      }));

  expect(await client.acceptAddressOnTCPPort('192.168.0.100', 2223), isTrue);

  expect(
      await client.listAcceptedAddressesOnTCPPorts(),
      equals(<({String address, int port})>{
        (address: '192.168.0.100', port: 2224),
        (address: '192.168.0.100', port: 2223),
      }));

  (await client.unacceptAddressOnTCPPort('192.168.0.100', 2224), isTrue);

  expect(
      await client.listAcceptedAddressesOnTCPPorts(),
      equals(<({String address, int port})>{
        (address: '192.168.0.100', port: 2223),
      }));

  (await client.unacceptAddressOnTCPPort('192.168.0.100', 2223), isTrue);

  expect(await client.listAcceptedAddressesOnTCPPorts(),
      equals(<({String address, int port})>{}));

  expect(await client.unblockTCPPort(2224), isTrue);
  expect(await client.listBlockedTCPPorts(), equals(<int>{}));

  client.close();
  expect(client.isConnected, isFalse);

  gatekeeperServer.close();
  expect(gatekeeperServer.isStarted, isFalse);
}
