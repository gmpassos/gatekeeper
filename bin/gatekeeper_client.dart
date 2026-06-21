import 'dart:io';

import 'package:args_simple/args_simple.dart';
import 'package:gatekeeper/gatekeeper_client.dart';

void main(List<String> argsOrig) async {
  var args = ArgsSimple.parse(argsOrig);

  // Optional configuration loaded from the `.gatekeeper` directory at the
  // current user's home (resolved on all OSes supported by Dart):
  final config = GatekeeperClientConfig.load();

  if (args.flag('h') || args.isEmpty && config.host == null) {
    _showHelp();
    exit(0);
  }

  final host = args.argumentAsString(0, config.host);
  if (host == null || host.isEmpty) {
    throw ArgumentError("Invalid host!");
  }

  final port = args.argumentAsInt(1, config.port) ??
      (throw ArgumentError("Invalid port!"));

  final verbose = args.flagOr('verbose', config.verbose) ?? config.verbose;

  final client = GatekeeperClient(host, port, verbose: verbose);

  print('[Gatekeeper - Client / $gatekeeperVersion]\n');

  var accessKey = _resolveAccessKey(args, config);

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
      '-- Logged to `GatekeeperServer` @ $host:$port [${login.serverVersion}]');

  print('------------------------------------------------------');
  print('Type `help` or `?` to list the available commands.');

  while (client.isConnected) {
    stdout.write('> ');
    var cmd = stdin.readLineSync()?.trim();
    await client.processCommand(cmd);
  }

  print('By!');
  exit(0);
}

/// Resolves the access key, in order of precedence:
/// 1. The `--access-key` option (use `-` or `.` to read from `stdin`).
/// 2. The access key provided by the `.gatekeeper` directory.
/// 3. An interactive prompt.
String? _resolveAccessKey(ArgsSimple args, GatekeeperClientConfig config) {
  var accessKey = args.optionAsString('access-key');

  if (accessKey == '-' || accessKey == '.') {
    accessKey = stdin.readLineSync()?.trim();
  }

  accessKey ??= config.accessKey;

  if (accessKey == null || accessKey.isEmpty || accessKey == '?') {
    stdout.write('Access-Key: ');
    accessKey = stdin.readLineSync()?.trim();
  }

  return accessKey;
}

void _showHelp() {
  print('[Gatekeeper - Client / $gatekeeperVersion]\n');
  print('USAGE:');
  print('  gatekeeper_client %host %port --access-key %key-length-32+');
  print('');
  print('CONFIGURATION (`.gatekeeper` directory at the user home):');
  print('  ~/.gatekeeper/config.json  '
      'JSON with optional `host`, `port`, `access-key` and `verbose`.');
  print('  ~/.gatekeeper/access-key   '
      'Plain text file with the access key (optional).');
  print('');
}
