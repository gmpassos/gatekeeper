import 'package:gatekeeper/gatekeeper_client.dart';
import 'package:gatekeeper/gatekeeper_server.dart';
import 'package:test/test.dart';

const accessKey = '0123456789abcdefghijklmnopqrstuvwxyz';

void main() {
  group('GatekeeperClient dual-stack', () {
    test('myIP / myIPs / accept . / unaccept . (secure)',
        () => _testDualStack(secure: true),
        timeout: Timeout(Duration(minutes: 1)));

    test('myIP / myIPs / accept . / unaccept . (insecure)',
        () => _testDualStack(secure: false),
        timeout: Timeout(Duration(minutes: 1)));
  });
}

Future<void> _testDualStack({required bool secure}) async {
  final listenPort = 2245;

  final driver = GatekeeperMock();

  final server = GatekeeperServer(
    Gatekeeper(driver: driver, allowAllPorts: true),
    listenPort: listenPort,
    accessKey: accessKey,
  );

  expect(await server.start(), isTrue);

  try {
    final client = GatekeeperClient('localhost', listenPort, secure: secure);

    expect(await client.connect(), isTrue);
    expect((await client.login(accessKey)).ok, isTrue);

    // `myip`: the current connection's server-visible loopback address.
    var ip = await client.myIP();
    expect(ip, anyOf(equals('127.0.0.1'), equals('::1')));

    // `myIPs`: should discover BOTH families via an auxiliary connection.
    var ips = await client.myIPs();
    expect(ips.ipv4, equals('127.0.0.1'));
    expect(ips.ipv6, equals('::1'));

    // `accept . <port>`: whitelists both families.
    expect(await client.processCommand('accept . 2223'), isTrue);

    expect(
        await client.listAcceptedAddressesOnTCPPorts(),
        equals(<({String address, int port})>{
          (address: '127.0.0.1', port: 2223),
          (address: '::1', port: 2223),
        }));

    // `unaccept . <port>`: removes both families.
    expect(await client.processCommand('unaccept . 2223'), isTrue);

    expect(await client.listAcceptedAddressesOnTCPPorts(),
        equals(<({String address, int port})>{}));

    client.close();
    expect(client.isConnected, isFalse);
  } finally {
    server.close();
  }
}
