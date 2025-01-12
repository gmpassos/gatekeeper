import 'dart:io';

import 'package:args_simple/args_simple.dart';
import 'package:gatekeeper/gatekeeper_client.dart';

void main(List<String> argsOrig) async {
  var args = ArgsSimple.parse(argsOrig);

  if (args.isEmpty) {
    _showHelp();
    exit(0);
  }

  final host = args.argumentAsString(0).toString();
  final port = args.argumentAsInt(1) ?? (throw ArgumentError("Invalid port!"));
  final verbose = args.flagOr('verbose', false) ?? false;

  final client = GatekeeperClient(host, port, verbose: verbose);

  print('[Gatekeeper - Client]\n');

  stdout.write('Access-Key: ');
  var accessKey = stdin.readLineSync()?.trim();

  if (accessKey == null || accessKey.length < 32) {
    throw ArgumentError("Invalid access-key> length: ${accessKey?.length}");
  }

  var connected = await client.connect();
  if (!connected) {
    throw StateError("Can't connect `GatekeeperClient` to: $host:$port");
  }

  print('** Running: $client');

  var login = await client.login(accessKey);
  if (!login.ok) {
    throw StateError("Login error!");
  }

  print(
      '-- Logged at `GatekeeperServer` @ $host:$port [${login.serverVersion}]');

  print('------------------------------------------------------');

  while (client.isConnected) {
    stdout.write('> ');
    var cmd = stdin.readLineSync()?.trim();
    await client.processCommand(cmd);
  }

  print('By!');
  exit(0);
}

void _showHelp() {
  print('[Gatekeeper - Client]\n');
  print('USAGE:');
  print('  gatekeeper_client %host %port --access-key %key-length-32+');
  print('');
}
