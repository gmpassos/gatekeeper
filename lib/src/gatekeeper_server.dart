import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:gatekeeper/src/utils.dart';

import 'gatekeeper_base.dart';

/// The [GatekeeperServer] class represents a server that interacts with a [Gatekeeper]
/// instance to manage connections and access control. It listens for incoming connections
/// on a specified port and address, using an `accessKey` for security authentication.
///
/// Example usage:
/// ```dart
/// var gatekeeper = Gatekeeper(driver: gatekeeperDriver);
/// var server = GatekeeperServer(gatekeeper, accessKey: 'mySecretKeyOfLength32+', listenPort: 2243);
/// await server.start();
/// ```
class GatekeeperServer {
  /// The [Gatekeeper] instance that the server uses for access control.
  final Gatekeeper gatekeeper;

  /// The access key required to authenticate connections. Minimal length: 32
  final String accessKey;

  /// The port the server listens on for incoming connections.
  final int listenPort;

  /// The address the server binds to. Defaults to [InternetAddress.anyIPv4] if not specified.
  final Object address;

  /// Creates a [GatekeeperServer] instance.
  ///
  /// - [gatekeeper]: the [Gatekeeper] instance.
  /// - [accessKey]: the access key for login.
  /// - [listenPort]: the port to listen for connections. NO default port for security purpose.
  /// - [address]: Optional addresses to bind. See [ServerSocket.bind]. Default: [InternetAddress.anyIPv4]
  GatekeeperServer(this.gatekeeper,
      {required this.accessKey, required this.listenPort, Object? address})
      : address = address ?? InternetAddress.anyIPv4 {
    if (accessKey.length < 32) {
      throw ArgumentError(
          "Invalid `accessKey` length: ${accessKey.length} < 32");
    }
  }

  late final Zone _zoneGuarded;

  static void _onUncaughtError(Zone self, ZoneDelegate parent, Zone zone,
      Object error, StackTrace stackTrace) {
    print('[ERROR]: $error');
    print(stackTrace);
  }

  ServerSocket? _server;

  /// A flag indicating whether the server has started and is listening for connections.
  bool get isStarted => _server != null;

  /// Starts the server and begins listening for incoming connections.
  ///
  /// Returns a [Future] that completes with `true` if the server successfully starts,
  /// or `false` if it is already running.
  ///
  /// Throws a [StateError] if the [Gatekeeper] cannot resolve.
  Future<bool> start() async {
    if (isStarted) return false;

    _zoneGuarded = Zone.current.fork(
        specification:
            ZoneSpecification(handleUncaughtError: _onUncaughtError));

    var started = await _zoneGuarded.run(_startImpl);
    if (!started) {
      throw StateError("Can't start `GatekeeperServer`");
    }

    var ok = await gatekeeper.resolve();
    if (!ok) {
      throw StateError("Can't resolve `Gatekeeper`");
    }

    return true;
  }

  Future<bool> _startImpl() async {
    var server = _server = await ServerSocket.bind(address, listenPort);
    server.listen(_onAcceptSocket);
    return true;
  }

  void _onAcceptSocket(Socket socket) {
    _SocketHandler(socket, this);
  }

  /// Closes the server and stops listening for new connections.
  void close() {
    _server?.close();
    _server = null;
  }

  @override
  String toString() {
    return 'GatekeeperServer{listenPort: $listenPort, address: $address}@$gatekeeper';
  }
}

class _SocketHandler {
  final Socket socket;
  final DateTime initTime = DateTime.now();

  final GatekeeperServer server;

  late final String remoteAddress;

  _SocketHandler(this.socket, this.server) {
    socket.listen(_onData);
    remoteAddress = socket.remoteAddress.address;
    _log("Accepted `Socket`.");
  }

  Gatekeeper get gatekeeper => server.gatekeeper;

  String get accessKey => server.accessKey;

  final List<Uint8List> _allData = [];
  int _allDataLength = 0;

  void _onData(Uint8List block) {
    _allData.add(block);
    _allDataLength += block.length;
    _processData();
  }

  Uint8List _compactData() {
    if (_allData.isEmpty) {
      return Uint8List(0);
    } else if (_allData.length < 2) {
      return _allData.first;
    }

    var fullData = _allData.reduce((block1, block2) => block1.merge(block2));

    _allData.clear();
    _allData.add(fullData);

    return fullData;
  }

  void _removeData(int length) {
    if (_allData.isEmpty) {
      return;
    }

    final fullData = _compactData();
    if (length > fullData.length) {
      length = fullData.length;
    }

    var rest = fullData.sublist(length);

    var offset = 0;
    while (offset < rest.length) {
      var c0 = rest[offset];
      if (c0 == 10 || c0 == 13 || c0 == 32) {
        ++offset;
      } else {
        break;
      }
    }

    if (offset > 0) {
      rest = rest.sublist(offset);
    }

    _allData.clear();
    _allData.add(rest);

    // print('<<${latin1.decode(rest)}>>');
  }

  void _processData() async {
    if (_allDataLength < 4) {
      return;
    }

    if (_allDataLength > 1024) {
      close();
      return;
    }

    var fullData = _compactData();

    // print("<${latin1.decode(fullData)}>");

    var idxSpace = fullData.indexOf(32);
    var idxNewLine = fullData.indexOf(10);

    if (idxSpace < 0) {
      if (idxNewLine >= 0) {
        close();
      }
      return;
    }

    if (idxSpace <= 1) {
      close();
      return;
    }

    if (idxNewLine < 0) {
      return;
    }

    if (idxNewLine < idxSpace) {
      close();
      return;
    }

    var cmd = latin1.decode(fullData.sublist(0, idxSpace)).trim();
    var args = latin1.decode(fullData.sublist(idxSpace + 1, idxNewLine)).trim();

    var processed = await _processCommand(cmd, args);

    if (processed == null) {
      _allData.clear();
      close();
    } else if (processed) {
      _removeData(idxNewLine + 1);
    }
  }

  bool _logged = false;
  int _loginCount = 0;

  Future<bool?> _processCommand(String cmd, String args) async {
    switch (cmd) {
      case 'login':
        {
          ++_loginCount;

          var key = args.trim();

          await Future.delayed(Duration(milliseconds: 300));

          if (accessKey == key) {
            _logged = true;
            socket.writeln("login: true");

            _log('LOGIN');

            return true;
          } else {
            socket.writeln("login: false");
            if (_loginCount > 10) {
              close();
              return null;
            }
          }
        }

      case 'list':
        {
          if (!_logged) {
            close();
            return null;
          }

          args = args.trim();

          if (args == 'ports') {
            var blockedPorts = await gatekeeper.listBlockedTCPPorts();
            socket.writeln("blocked: ${blockedPorts.join(', ')}");

            _log('List ports.');

            return true;
          } else if (args == 'accepts') {
            var acceptedAddresses =
                await gatekeeper.listAcceptedAddressesOnTCPPorts();

            var response = acceptedAddresses
                .map((e) => '${e.address}:${e.port}')
                .join('; ');

            socket.writeln(response);

            _log('List accepted addresses.');

            return true;
          } else {
            close();
            return null;
          }
        }

      case 'block':
        {
          if (!_logged) {
            close();
            return null;
          }

          var port = int.tryParse(args.trim());

          if (port != null && port >= 10) {
            var ok = await gatekeeper.blockTCPPort(port);
            socket.writeln("block: $ok");

            _log('BLOCKED PORT: $port');

            return true;
          } else {
            close();
            return null;
          }
        }

      case 'unblock':
        {
          if (!_logged) {
            close();
            return null;
          }

          var port = int.tryParse(args.trim());

          if (port != null && port >= 10) {
            var ok = await gatekeeper.unblockTCPPort(port);
            socket.writeln("unblock: $ok");

            _log('UNBLOCKED PORT: $port');

            return true;
          } else {
            close();
            return null;
          }
        }

      case 'accept':
        {
          if (!_logged) {
            close();
            return null;
          }

          var parts = args.split(RegExp(r'\s+'));
          if (parts.length != 2) {
            close();
            return null;
          }

          var address = parts[0].trim();
          var port = int.tryParse(parts[1].trim());

          if (address.isNotEmpty && port != null && port >= 10) {
            if (address == '.') {
              address = remoteAddress;
            }

            var ok = await gatekeeper.acceptAddressOnTCPPort(address, port);
            socket.writeln("accepted: $ok ($address -> $port)");

            _log('ACCEPTED: $address -> $port');

            return true;
          } else {
            close();
            return null;
          }
        }

      case 'unaccept':
        {
          if (!_logged) {
            close();
            return null;
          }

          var parts = args.split(RegExp(r'\s+'));
          if (parts.length > 2) {
            close();
            return null;
          }

          var address = parts[0].trim();
          var port = parts.length > 1 ? int.tryParse(parts[1].trim()) : null;

          if (address.isNotEmpty && (port == null || port >= 10)) {
            if (address == '.') {
              address = remoteAddress;
            }

            var ok = await gatekeeper.unacceptAddressOnTCPPort(address, port);
            socket.writeln("unaccepted: $ok ($address -> $port)");

            _log('UNACCEPTED: $address -> $port');

            return true;
          } else {
            close();
            return null;
          }
        }

      case 'disconnect':
        {
          socket.writeln("disconnect: true");
          socket.close();

          _log('DISCONNECT');

          return true;
        }

      default:
        {
          close();

          _log('CLOSE - Unknown command: $cmd');

          return null;
        }
    }

    return null;
  }

  void _log(String msg) {
    var now = DateTime.now();
    var time = '$now'.padRight(26, '0');
    print('$time [$remoteAddress] $msg');
  }

  void close() {
    socket.close();
    _allData.clear();
  }
}
