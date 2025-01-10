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

  final client = GatekeeperClient(host, port);

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

  var logged = await client.login(accessKey);
  if (!logged) {
    throw StateError("Login error!");
  }

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
