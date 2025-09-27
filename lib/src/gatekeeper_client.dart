import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'crypto.dart';
import 'crypto_utils.dart' as crypto_utils;
import 'gatekeeper_const.dart';
import 'socket_base.dart';

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
class GatekeeperClient extends SocketClientBase {
  /// If `true` use a secure layer for communication.
  final bool secure;

  /// Creates a new [GatekeeperClient] instance.
  ///
  /// - [host]: The host address of the [GatekeeperServer].
  /// - [port]: The port number on which the [GatekeeperServer] is listening.
  GatekeeperClient(super.host, super.port, {this.secure = true, super.verbose});

  AESEncryptor? _aesEncryptor;

  AESEncryptor get aesEncryptor => _aesEncryptor ??= AESEncryptor(_accessKey ??
      (throw StateError("`_accessKey` not defined yet! Call `login` first.")));

  ChainAESEncryptor? _chainAESEncryptor;

  ChainAESEncryptor get chainAESEncryptor =>
      _chainAESEncryptor ??= ChainAESEncryptor(
        aesEncryptor,
        server: false,
        seed1: (remotePort ?? (throw StateError("Null `Socket`"))),
      );

  @override
  Future<String?> sendCommand(String command,
      {Duration responseTimeout = const Duration(seconds: 30)}) async {
    if (secure) {
      var enc = chainAESEncryptor.encryptMessage(command);
      command = '_: $enc';
    }

    var responseMsg = await super.sendCommand(command);

    if (responseMsg != null && secure) {
      responseMsg = _decryptMsg(responseMsg);
    }

    return responseMsg;
  }

  String? _decryptMsg(String responseMsg) {
    if (secure && !responseMsg.startsWith('_: ')) {
      close();
      throw StateError("Insecure Server!");
    }

    if (responseMsg.startsWith('_: ')) {
      var encryptedMsg = responseMsg.substring(3);
      responseMsg = chainAESEncryptor.decryptMessage(encryptedMsg);
    }

    return responseMsg;
  }

  bool _logged = false;

  /// A flag indicating whether this client is logged.
  bool get isLogged => _logged;

  String? _accessKey;

  /// Logs in to the [GatekeeperServer] using the provided access key.
  ///
  /// - [accessKey]: The access key used to authenticate the login.
  ///
  /// Returns a [Future] that completes with `(ok: true, serverVersion: 'x.x.x'})` if login was successful,
  /// or `(ok: false, serverVersion: null})` if it failed.
  Future<({bool ok, String? serverVersion})> login(String accessKey) async {
    _accessKey = accessKey;

    if (secure) {
      var ok = await _exchangeSessionKey();
      if (!ok) return (ok: false, serverVersion: null);
    }

    var sessionKey = chainAESEncryptor.sessionKey;

    var accessKeyHash = hashAccessKey(accessKey, sessionKey: sessionKey);
    var accessKeyBase64 = base64.encode(accessKeyHash);

    var response = await sendCommand("login $accessKeyBase64");

    var logged = false;
    String? serverVersion;

    if (response != null && response.isNotEmpty) {
      logged = response.contains('true');
      if (logged) {
        _logged = true;
      }

      serverVersion = RegExp(r'\[(.*?)]').firstMatch(response)?.group(1);
    }

    if (verbose) {
      print(
          '-- LOGIN: $logged ${serverVersion != null ? '[$serverVersion]' : ''}');
    }

    return (ok: true, serverVersion: serverVersion);
  }

  Future<bool> _exchangeSessionKey() async {
    var exchange = crypto_utils.generateExchangeKey(aesEncryptor.aesKey);

    // if (verbose) {
    //   print(
    //       '-- Exchange SessionKey> exchangeKeyEncrypted: ${base16.encode(exchange.exchangeKeyEncrypted)}');
    // }

    var exchangeKeyEncryptedStr =
        String.fromCharCodes(exchange.exchangeKeyEncrypted);

    var response = await sendCommand(exchangeKeyEncryptedStr);
    if (response == null) {
      close();
      return false;
    }

    var sessionKeyEncrypted = Uint8List.fromList(response.codeUnits);

    var exchangeKey = exchange.exchangeKey;
    if (exchangeKey.length > 32) {
      exchangeKey = Uint8List.fromList(exchangeKey.sublist(0, 32));
    }

    var sessionKey = crypto_utils.decryptSessionKey(
      aesEncryptor.aesKey,
      crypto_utils.decryptSessionKey(
        exchangeKey,
        sessionKeyEncrypted,
      ),
    );

    if (sessionKey.length > 32) {
      sessionKey = Uint8List.fromList(sessionKey.sublist(0, 32));
    }

    chainAESEncryptor.sessionKey = sessionKey;

    if (verbose) {
      print('-- SESSION KEY DEFINED.');
    }

    return true;
  }

  /// Lists the TCP ports that are currently blocked.
  ///
  /// Returns a [Future] that completes with a [Set] of blocked ports.
  Future<Set<int>> listBlockedTCPPorts() async {
    var response = await sendCommand("list ports");
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
    var response = await sendCommand("block $port");
    return response?.contains('true') ?? false;
  }

  /// Unblocks a specific TCP port.
  ///
  /// - [port]: The TCP port to unblock.
  ///
  /// Returns a [Future] that completes with `true` if the port was successfully unblocked,
  /// or `false` if it failed.
  Future<bool> unblockTCPPort(int port) async {
    var response = await sendCommand("unblock $port");
    return response?.contains('true') ?? false;
  }

  /// Lists the accepted addresses on TCP ports.
  ///
  /// Returns a [Future] that completes with a [Set] of `({String address, int port}` entries.
  Future<Set<({String address, int port})>>
      listAcceptedAddressesOnTCPPorts() async {
    var response = await sendCommand("list accepts");
    if (response == null) return {};

    var entries = response
        .trim()
        .split(RegExp(r';'))
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
    var response = await sendCommand("accept $address $port");
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
    var response = await sendCommand("unaccept $address $port");
    return response?.contains('true') ?? false;
  }

  /// Send a disconnect command, remotely closing the [Socket].
  /// Used by `exit` command. See [processCommand].
  Future<bool> disconnect() async {
    var response = await sendCommand("disconnect socket");
    return response?.contains('true') ?? false;
  }

  /// Retrieves the IP address of this client as seen by the remote server.
  Future<String?> myIP() async {
    var response = await sendCommand("myip .");
    if (response == null || response.isEmpty) return null;

    var match = RegExp(r'ip:\s+(\S+)').firstMatch(response);
    var ip = match?.group(1);

    return ip;
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

    var parts = command.split(RegExp(r'\s+'));

    var cmd = parts[0].trim().toLowerCase();

    switch (cmd) {
      case 'l':
      case 'ls':
      case 'list':
        {
          var type = parts.length > 1 ? parts[1].trim().toLowerCase() : 'all';

          switch (type) {
            case 'port':
            case 'ports':
            case 'block':
            case 'blocks':
            case 'blocked':
              {
                var ports = await listBlockedTCPPorts();
                print('-- Blocked ports: $ports');
                return true;
              }

            case 'address':
            case 'addresses':
            case 'accept':
            case 'accepts':
            case 'accepted':
              {
                var accepts = await listAcceptedAddressesOnTCPPorts();
                print('-- Accepted addresses: $accepts');
                return true;
              }

            case 'all':
              {
                var ports = await listBlockedTCPPorts();
                print('-- Blocked ports: $ports');

                var accepts = await listAcceptedAddressesOnTCPPorts();
                print('-- Accepted addresses: $accepts');

                return true;
              }

            default:
              {
                print('** Unknown list type: $type');
                return false;
              }
          }
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

      case 'accept':
        {
          var address = parts[1].trim();
          if (address.isEmpty) {
            print('** Empty address');
            return false;
          }

          var port = int.tryParse(parts[2].trim());
          if (port == null || port < 10) {
            print('** Invalid port: $port');
            return false;
          }

          var accepted = await acceptAddressOnTCPPort(address, port);
          print('-- Accepted address `$address` on port $port: $accepted');
          return true;
        }

      case 'unaccept':
        {
          var address = parts[1].trim();
          if (address.isEmpty) {
            print('** Empty address');
            return false;
          }

          var port = parts.length > 2 ? int.tryParse(parts[2].trim()) : null;

          var unaccepted = await unacceptAddressOnTCPPort(address, port);
          print(
              '-- Unaccepted address `$address` on port ${port ?? '*'}: $unaccepted');
          return true;
        }

      case 'myip':
        {
          var ip = await myIP();
          print('-- My IP: $ip');

          return true;
        }

      case 'my':
        {
          var type = parts.length > 1 ? parts[1].trim().toLowerCase() : '';

          if (type == 'ip') {
            var ip = await myIP();
            print('-- My IP: $ip');

            return true;
          }

          return false;
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

  @override
  String toString() =>
      'GatekeeperClient[$gatekeeperVersion]{host: $host, port: $port, logged: $isLogged}';
}
