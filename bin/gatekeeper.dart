import 'dart:io';

import 'package:args_simple/args_simple.dart';
import 'package:gatekeeper/gatekeeper_server.dart';

void main(List<String> argsOrig) async {
  var args = ArgsSimple.parse(argsOrig);

  if (args.isEmpty) {
    _showHelp();
    exit(0);
  }

  final listenPort = args.optionAsInt('port');
  if (listenPort == null || listenPort < 10) {
    throw ArgumentError("Invalid port: $listenPort");
  }

  var accessKey = args.optionAsString('access-key');

  if (accessKey == null) {
    stdout.write('Access-Key: ');
    accessKey = stdin.readLineSync()?.trim();
  }

  if (accessKey == null || accessKey.length < 32) {
    throw ArgumentError("Invalid access-key> length: ${accessKey?.length}");
  }

  var allowedPorts = args
      .optionAsList('allowed-ports')
      ?.map((e) => int.tryParse('$e'.trim()))
      .nonNulls
      .toSet();

  var allowAllPorts = args.flagOr('allow-all-ports', false) ?? false;

  final driver = GatekeeperIpTables();
  final gatekeeper = Gatekeeper(
      driver: driver, allowedPorts: allowedPorts, allowAllPorts: allowAllPorts);

  final server = GatekeeperServer(
    gatekeeper,
    accessKey: accessKey,
    listenPort: listenPort,
  );

  var started = await server.start();
  if (!started) {
    throw StateError("Can't start `GatekeeperServer` at port: $listenPort");
  }

  print('** Running: $server');
}

void _showHelp() {
  print('[Gatekeeper - Server]\n');
  print('USAGE:');
  print(
      '  gatekeeper --port %port --access-key %key-length-32+ --allowed-ports %p1,%p2,%p3 -allow-all-ports');
  print('');
}
