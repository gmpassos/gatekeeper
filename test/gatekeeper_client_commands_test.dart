import 'package:gatekeeper/gatekeeper_client.dart';
import 'package:gatekeeper/gatekeeper_server.dart';
import 'package:test/test.dart';

const accessKey = '0123456789abcdefghijklmnopqrstuvwxyz';

void main() {
  group('GatekeeperClient.processCommand', () {
    late GatekeeperServer server;
    late GatekeeperClient client;
    const listenPort = 2246;

    setUp(() async {
      server = GatekeeperServer(
        Gatekeeper(driver: GatekeeperMock(), allowedPorts: {2223, 2224}),
        listenPort: listenPort,
        accessKey: accessKey,
      );
      expect(await server.start(), isTrue);

      client = GatekeeperClient('localhost', listenPort, secure: true);
      expect(await client.connect(), isTrue);
      expect((await client.login(accessKey)).ok, isTrue);
    });

    tearDown(() {
      client.close();
      server.close();
    });

    test('block / unblock commands', () async {
      expect(await client.processCommand('block 2223'), isTrue);
      expect(await client.listBlockedTCPPorts(), equals({2223}));

      expect(await client.processCommand('unblock 2223'), isTrue);
      expect(await client.listBlockedTCPPorts(), equals(<int>{}));

      // Invalid ports are rejected client-side.
      expect(await client.processCommand('block abc'), isFalse);
      expect(await client.processCommand('block 5'), isFalse);
      expect(await client.processCommand('unblock abc'), isFalse);
    });

    test('accept / unaccept literal address', () async {
      expect(await client.processCommand('accept 1.2.3.4 2223'), isTrue);
      expect(
          await client.listAcceptedAddressesOnTCPPorts(),
          equals(<({String address, int port})>{
            (address: '1.2.3.4', port: 2223),
          }));

      expect(await client.processCommand('unaccept 1.2.3.4 2223'), isTrue);
      expect(await client.listAcceptedAddressesOnTCPPorts(),
          equals(<({String address, int port})>{}));
    });

    test('accept invalid arguments', () async {
      expect(await client.processCommand('accept 1.2.3.4'), isFalse); // no port
      expect(await client.processCommand('accept 1.2.3.4 5'), isFalse); // <10
      expect(await client.processCommand('unaccept'), isFalse); // no address
    });

    test('list variants', () async {
      await client.processCommand('block 2223');
      await client.processCommand('accept 1.2.3.4 2224');

      expect(await client.processCommand('list ports'), isTrue);
      expect(await client.processCommand('l blocked'), isTrue);
      expect(await client.processCommand('ls accepts'), isTrue);
      expect(await client.processCommand('list addresses'), isTrue);
      expect(await client.processCommand('list all'), isTrue);
      expect(await client.processCommand('list'), isTrue); // default: all
      expect(await client.processCommand('list bogus'), isFalse);
    });

    test('myip / my ip', () async {
      expect(await client.processCommand('myip'), isTrue);
      expect(await client.processCommand('my ip'), isTrue);
      expect(await client.processCommand('my something'), isFalse);

      var ip = await client.myIP();
      expect(ip, anyOf(equals('127.0.0.1'), equals('::1')));
    });

    test('help / ? / unknown', () async {
      expect(await client.processCommand('help'), isTrue);
      expect(await client.processCommand('?'), isTrue);
      expect(await client.processCommand('bogus-cmd'), isFalse);
      expect(await client.processCommand(''), isFalse);
      expect(await client.processCommand(null), isFalse);
    });

    test('disconnect', () async {
      expect(await client.disconnect(), isTrue);
    });
  });
}
