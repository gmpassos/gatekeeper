import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:gatekeeper/src/utils.dart';

/// The [GatekeeperClient] class allows a client to connect to a [GatekeeperServer]
/// and interact with it by sending commands such as login, listing blocked TCP ports,
/// and blocking or unblocking specific TCP ports. It uses a socket connection to
/// communicate with the server and expects responses in a specific format.
///
/// Example usage:
/// ```dart
/// var client = GatekeeperClient('localhost', 2243);
/// await client.connect();
/// await client.login('accessKey123');
/// await client.listBlockedTCPPorts();
/// ```
class GatekeeperClient {
  /// The host (IP address or hostname) of the [GatekeeperServer].
  final String host;

  /// The port on which the [GatekeeperServer] is listening.
  final int port;

  /// Creates a new [GatekeeperClient] instance.
  ///
  /// - [host]: The host address of the [GatekeeperServer].
  /// - [port]: The port number on which the [GatekeeperServer] is listening.
  GatekeeperClient(this.host, this.port);

  Socket? _socket;

  /// A flag indicating whether the client is connected to the server.
  bool get isConnected => _socket != null;

  Uint8List _receivedData = Uint8List(0);

  Completer<Uint8List?>? _waitingData;

  /// Connects to the Gatekeeper server.
  ///
  /// Returns a [Future] that completes with `true` if the connection was successful,
  /// or `false` if already connected.
  Future<bool> connect() async {
    if (isConnected) return false;
    var socket = _socket = await Socket.connect(host, port);

    socket.listen(_onData, cancelOnError: true, onDone: _onClose);

    return true;
  }

  void _onClose() {
    close();
  }

  void _onData(Uint8List data) {
    var fullData = _receivedData = _receivedData.merge(data);

    final waitingData = _waitingData;
    if (waitingData != null) {
      if (waitingData.isCompleted) {
        _waitingData = null;
        return;
      }

      var idx = fullData.indexOf(10);
      if (idx < 0) {
        return;
      }

      var response = fullData.sublist(0, idx);
      _receivedData = fullData.sublist(idx + 1);

      _waitingData = null;
      waitingData.complete(response);
    }
  }

  Socket _connectedSocket() =>
      _socket ?? (throw StateError("`Socket` not connected!"));

  Future<String?> _sendCommand(String command) async {
    final socket = _connectedSocket();

    var waitingData = _waitingData;
    while (waitingData != null) {
      await waitingData.future;
      waitingData = _waitingData;
    }

    waitingData = _waitingData = Completer<Uint8List?>();

    socket.writeln(command);

    var response = await waitingData.future
        .timeout(Duration(seconds: 30), onTimeout: () => null);

    if (identical(waitingData, _waitingData)) {
      _waitingData = null;
    }

    return response != null ? latin1.decode(response) : null;
  }

  bool _logged = false;

  /// A flag indicating whether this client is logged.
  bool get isLogged => _logged;

  /// Logs in to the [GatekeeperServer] using the provided access key.
  ///
  /// - [accessKey]: The access key used to authenticate the login.
  ///
  /// Returns a [Future] that completes with `true` if login was successful,
  /// or `false` if it failed.
  Future<bool> login(String accessKey) async {
    var response = await _sendCommand("login $accessKey");
    var logged = response?.contains('true') ?? false;
    if (logged) {
      _logged = true;
    }
    return logged;
  }

  /// Lists the TCP ports that are currently blocked.
  ///
  /// Returns a [Future] that completes with a [Set] of blocked ports.
  Future<Set<int>> listBlockedTCPPorts() async {
    var response = await _sendCommand("list ports");
    if (response == null) return {};

    response = response.split(':')[1];

    var ports = response
        .trim()
        .split(RegExp(r'\D+'))
        .map((e) => int.tryParse(e))
        .nonNulls
        .toSet();

    return ports;
  }

  /// Blocks a specific TCP port.
  ///
  /// - [port]: The TCP port to block.
  ///
  /// Returns a [Future] that completes with `true` if the port was successfully blocked,
  /// or `false` if it failed.
  Future<bool> blockTCPPort(int port) async {
    var response = await _sendCommand("block $port");
    return response?.contains('true') ?? false;
  }

  /// Unblocks a specific TCP port.
  ///
  /// - [port]: The TCP port to unblock.
  ///
  /// Returns a [Future] that completes with `true` if the port was successfully unblocked,
  /// or `false` if it failed.
  Future<bool> unblockTCPPort(int port) async {
    var response = await _sendCommand("unblock $port");
    return response?.contains('true') ?? false;
  }

  Future<Set<({String address, int port})>>
      listAcceptedAddressesOnTCPPorts() async {
    var response = await _sendCommand("list accepts");
    if (response == null) return {};

    var entries = response
        .trim()
        .split(RegExp(r'\n'))
        .map((e) => e.trim())
        .where((e) => e.isNotEmpty)
        .map((e) {
          var parts = e.split(':');
          if (parts.length != 2) return null;
          var a = parts[0];
          var p = int.tryParse(parts[1]);
          if (p == null) return null;
          return (address: a, port: p);
        })
        .nonNulls
        .toSet();

    return entries;
  }

  /// Adds a rule to accept a TCP connection from a specified [address] to the blocked [port].
  ///
  /// Parameters:
  /// - [address]: The IP address or hostname to accept connections from.
  /// - [port]: The port number to allow access to.
  ///
  /// Returns:
  /// A [Future<bool>] that resolves to `true` if successful, or `false` if the
  /// rule could not be added.
  Future<bool> acceptAddressOnTCPPort(String address, int port) async {
    address = address.trim();
    if (address.isEmpty) return false;
    var response = await _sendCommand("accept $address $port");
    return response?.contains('true') ?? false;
  }

  /// Reverses the acceptance ("unaccept") of an [address] on a specified TCP [port].
  ///
  /// - [address]: The IP address or hostname to unaccept.
  /// - [port]: The TCP port from which the address will be unaccepted. If `null` will remove from all ports.
  ///
  /// Returns:
  /// - A `Future<bool>` indicating whether the operation was successful.
  Future<bool> unacceptAddressOnTCPPort(String address, int? port) async {
    address = address.trim();
    if (address.isEmpty) return false;
    var response = await _sendCommand("unaccept $address $port");
    return response?.contains('true') ?? false;
  }

  /// Send a disconnect command, remotely closing the [Socket].
  /// Used by `exit` command. See [processCommand].
  Future<bool> disconnect() async {
    var response = await _sendCommand("disconnect socket");
    return response?.contains('true') ?? false;
  }

  /// Processes a command entered by the user.
  ///
  /// - [command]: The command line to execute.
  ///
  /// Returns a [Future] that completes with `true` if the command was processed,
  /// or `false` if the command was unrecognized or failed.
  Future<bool> processCommand(String? command) async {
    if (command == null) return false;
    command = command.trim();
    if (command.isEmpty) return false;

    var parts = command.split(' ');

    var cmd = parts[0].trim().toLowerCase();

    switch (cmd) {
      case 'l':
      case 'ls':
      case 'list':
        {
          var ports = await listBlockedTCPPorts();
          print('-- Blocked ports: $ports');
          return true;
        }

      case 'block':
        {
          var port = int.tryParse(parts[1].trim());
          if (port == null || port < 10) {
            print('** Invalid port: $port');
            return false;
          }

          var blocked = await blockTCPPort(port);
          print('-- Blocked $port: $blocked');
          return true;
        }

      case 'unblock':
        {
          var port = int.tryParse(parts[1].trim());
          if (port == null || port < 10) {
            print('** Invalid port: $port');
            return false;
          }

          var blocked = await unblockTCPPort(port);
          print('-- Unblocked $port: $blocked');
          return true;
        }

      case 'exit':
        {
          var ok = await disconnect();
          print('-- Disconnect: $ok');
          print('[EXIT] By!');
          exit(0);
        }

      default:
        {
          print('** Unknown command: `$cmd`');
          return false;
        }
    }
  }

  /// Closes the connection to the server.
  void close() {
    _socket?.close();
    _socket = null;
    _receivedData = Uint8List(0);

    var waitingData = _waitingData;
    if (waitingData != null) {
      if (!waitingData.isCompleted) {
        waitingData.complete(null);
      }
      _waitingData = null;
    }
  }

  @override
  String toString() =>
      'GatekeeperClient{host: $host, port: $port, logged: $isLogged}';
}
