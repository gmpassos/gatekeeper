import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:crypto/crypto.dart';

import 'crypto.dart';
import 'crypto_utils.dart';
import 'gatekeeper_base.dart';
import 'utils.dart';

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

  late final Uint8List accessKeyHash;

  /// The port the server listens on for incoming connections.
  final int listenPort;

  /// The address the server binds to. Defaults to [InternetAddress.anyIPv4] if not specified.
  final Object address;

  /// The maximum number of consecutive login errors allowed before
  /// blocking the remote address.
  final int loginErrorLimit;

  /// Defines the duration for which a remote address remains blocked
  /// after exceeding the login error limit.
  final Duration blockingTime;

  final bool verbose;

  /// Creates a [GatekeeperServer] instance.
  ///
  /// - [gatekeeper]: the [Gatekeeper] instance.
  /// - [accessKey]: the access key for login.
  /// - [listenPort]: the port to listen for connections. NO default port for security purpose.
  /// - [address]: Optional addresses to bind. See [ServerSocket.bind]. Default: [InternetAddress.anyIPv4]
  /// - [loginErrorLimit]: The limit of login errors to block a [Socket]. Default: 3 ; Minimal: 3
  /// - [blockingTime]: The [Socket] blocking time. Default: 10min
  GatekeeperServer(this.gatekeeper,
      {required this.accessKey,
      required this.listenPort,
      Object? address,
      int? loginErrorLimit,
      Duration? blockingTime,
      this.verbose = false})
      : address = address ?? InternetAddress.anyIPv4,
        loginErrorLimit = normalizeLoginErrorLimit(loginErrorLimit),
        blockingTime = normalizeBlockingTime(blockingTime) {
    if (accessKey.length < 32) {
      throw ArgumentError(
          "Invalid `accessKey` length: ${accessKey.length} < 32");
    }

    accessKeyHash = hashAccessKey(accessKey);
  }

  static int normalizeLoginErrorLimit(int? loginErrorLimit) {
    return math.max(loginErrorLimit ?? 3, 3);
  }

  static Duration normalizeBlockingTime(Duration? blockingTime) {
    return blockingTime != null && blockingTime.inMinutes >= 1
        ? blockingTime
        : Duration(minutes: 10);
  }

  late final Zone _zoneGuarded;

  static void _onUncaughtError(Zone self, ZoneDelegate parent, Zone zone,
      Object error, StackTrace stackTrace) {
    var now = DateTime.now();
    var time = '$now'.padRight(26, '0');
    print('$time [UNCAUGHT ERROR]: $error');
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

  late final AESEncryptor _aesEncryptor = AESEncryptor(accessKey);

  void _onAcceptSocket(Socket socket) {
    _SocketHandler(socket, this);
  }

  final Map<String, DateTime> _loginErrorLimit = {};

  bool _isSocketAddressBlocked(_SocketHandler socketHandler) {
    final remoteAddress = socketHandler.remoteAddress;

    var time = _loginErrorLimit[remoteAddress];
    if (time != null) {
      var elapsedTime = DateTime.now().difference(time);
      var blocked = elapsedTime < blockingTime;
      if (blocked) return true;
    }

    var errorStats = _socketError[remoteAddress];
    if (errorStats != null && errorStats.$1 > 3) {
      var elapsedTime = DateTime.now().difference(errorStats.$2);
      var blocked = elapsedTime < blockingTime;
      if (blocked) return true;
    }

    return false;
  }

  void _onLoginErrorLimit(_SocketHandler socketHandler) {
    var remoteAddress = socketHandler.remoteAddress;
    _loginErrorLimit[remoteAddress] = DateTime.now();
    print('-- `Socket` $remoteAddress login error limit!');
  }

  final Map<String, (int, DateTime)> _socketError = {};

  void _onSocketError(_SocketHandler socketHandler) {
    var remoteAddress = socketHandler.remoteAddress;
    var prev = _socketError[remoteAddress];

    if (prev != null) {
      prev = _socketError[remoteAddress] = (prev.$1 + 1, DateTime.now());
    } else {
      prev = _socketError[remoteAddress] = (1, DateTime.now());
    }

    print('-- `Socket` $remoteAddress error count: $prev');
  }

  /// Closes the server and stops listening for new connections.
  void close() {
    _server?.close();
    _server = null;
  }

  @override
  String toString() =>
      'GatekeeperServer[${Gatekeeper.VERSION}]{listenPort: $listenPort, address: $address}@$gatekeeper';
}

class _SocketHandler {
  final Socket socket;
  final DateTime initTime = DateTime.now();

  final GatekeeperServer server;

  late final String remoteAddress;
  StreamSubscription<Uint8List>? _socketSubscription;

  _SocketHandler(this.socket, this.server) {
    _socketSubscription =
        socket.listen(_onData, onError: _onError, onDone: _onClose);
    remoteAddress = socket.remoteAddress.address;

    if (server._isSocketAddressBlocked(this)) {
      close();
      _log("Blocked `Socket`: $remoteAddress");
    } else {
      _log("Accepted `Socket`: $remoteAddress");

      Future.delayed(Duration(seconds: 30), _checkLogged);
    }
  }

  void _checkLogged() {
    if (!_logged) {
      close();
      server._onSocketError(this);
      _log('`Socket` $remoteAddress login timeout!');
    }
  }

  void _onError(Object error, StackTrace stackTrace) {
    close();
    server._onSocketError(this);
    if (verbose) {
      print('-- `Socket` $remoteAddress error: $error');
    }
  }

  void _onClose() {
    close();
    if (verbose) {
      print('-- `Socket` $remoteAddress closed.');
    }
  }

  Gatekeeper get gatekeeper => server.gatekeeper;

  String get accessKey => server.accessKey;

  Uint8List get accessKeyHash => server.accessKeyHash;

  AESEncryptor get _aesEncryptor => server._aesEncryptor;

  ChainAESEncryptor? _chainAESEncryptor;

  ChainAESEncryptor get chainAESEncryptor =>
      _chainAESEncryptor ??= ChainAESEncryptor(
        _aesEncryptor,
        server: true,
        seed1: server.listenPort,
      );

  bool get verbose => server.verbose;

  final List<Uint8List> _allData = [];
  int _allDataLength = 0;

  void _onData(Uint8List block) async {
    _allData.add(block);
    _allDataLength += block.length;

    try {
      await _processData();
    } catch (e, s) {
      close();
      server._onSocketError(this);
      _log('-- onData> `Socket` $remoteAddress error: $e');
      print(s);
    }
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

  Future<void> _processData() async {
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

    if (verbose) {
      print('-- _processData: <<<${latin1.decode(fullData).trim()}>>>');
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

  void _sendResponse(String message, {required bool secure}) {
    if (secure) {
      var enc = chainAESEncryptor.encryptMessage(message);
      message = '_: $enc';
    }

    if (verbose) {
      print('-- _sendResponse: <<<$message>>>');
    }

    socket.writeln(message);
  }

  bool _logged = false;
  int _loginCount = 0;

  Future<bool?> _processCommand(String cmd, String args) async {
    var secure = false;
    if (cmd.startsWith('_:')) {
      var msg = chainAESEncryptor.decryptMessage(args);

      if (chainAESEncryptor.sessionKey == null) {
        return _exchangeSessionKey(msg);
      }

      var idx = msg.indexOf(' ');
      cmd = msg.substring(0, idx).trim();
      args = msg.substring(idx + 1);
      secure = true;
    }

    switch (cmd) {
      case 'login':
        {
          ++_loginCount;

          await Future.delayed(Duration(milliseconds: 300));

          var keyBase64 = args.trim();
          var keyBytes = base64.decode(keyBase64);

          if (_checkAccessKey(keyBytes,
              sessionKey: chainAESEncryptor.sessionKey)) {
            _logged = true;
            _sendResponse(
              "login: true [${Gatekeeper.VERSION}]",
              secure: secure,
            );

            _log('LOGIN');

            return true;
          } else {
            _sendResponse("login: false", secure: secure);
            _onLoginError();
            return null;
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
            _sendResponse("blocked: ${blockedPorts.join(', ')}",
                secure: secure);

            _log('List ports.');

            return true;
          } else if (args == 'accepts') {
            var acceptedAddresses =
                await gatekeeper.listAcceptedAddressesOnTCPPorts();

            var response = acceptedAddresses
                .map((e) => '${e.address}:${e.port}')
                .join('; ');

            _sendResponse(response, secure: secure);

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
            _sendResponse("block: $ok", secure: secure);

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
            _sendResponse("unblock: $ok", secure: secure);

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
            _sendResponse("accepted: $ok ($address -> $port)", secure: secure);

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
            _sendResponse("unaccepted: $ok ($address -> $port)",
                secure: secure);

            _log('UNACCEPTED: $address -> $port');

            return true;
          } else {
            close();
            return null;
          }
        }

      case 'disconnect':
        {
          _sendResponse("disconnect: true", secure: secure);
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
  }

  bool _exchangeSessionKey(String exchangeKeyEncryptedStr) {
    // if (verbose) {
    //   print(
    //       '-- Exchange SessionKey> exchangeKeyEncrypted: ${base16.encode(Uint8List.fromList(exchangeKeyEncryptedStr.codeUnits))}');
    // }

    var aesKey = _aesEncryptor.aesKey;

    var exchangeKey = decryptSessionKey(
      aesKey,
      Uint8List.fromList(exchangeKeyEncryptedStr.codeUnits),
    );

    if (exchangeKey.length > 32) {
      exchangeKey = Uint8List.fromList(exchangeKey.sublist(0, 32));
    }

    var sessionKey = generateRandomAESKey(randomLength: 32);

    var sessionKeyEncrypted = encryptSessionKey(
      exchangeKey,
      encryptSessionKey(aesKey, sessionKey),
    );

    var sessionKeyEncryptedStr = String.fromCharCodes(sessionKeyEncrypted);

    _sendResponse(sessionKeyEncryptedStr, secure: true);

    if (sessionKey.length > 32) {
      sessionKey = Uint8List.fromList(sessionKey.sublist(0, 32));
    }

    chainAESEncryptor.sessionKey = sessionKey;

    _log('SESSION');

    return true;
  }

  void _onLoginError() {
    if (_loginCount >= server.loginErrorLimit) {
      server._onLoginErrorLimit(this);
      close();
    }
  }

  static final ListEquality<int> _bytesEquality = ListEquality<int>();

  bool _checkAccessKey(Uint8List keyBytes, {Uint8List? sessionKey}) {
    List<int> hash;
    if (sessionKey != null && sessionKey.isNotEmpty) {
      hash = sha512.convert([...accessKeyHash, ...sessionKey]).bytes;
    } else {
      hash = accessKeyHash;
    }

    return _bytesEquality.equals(hash, keyBytes);
  }

  void _log(String msg) {
    var now = DateTime.now();
    var time = '$now'.padRight(26, '0');
    print('$time [$remoteAddress] $msg');
  }

  void close() {
    _socketSubscription?.cancel();
    _socketSubscription = null;
    socket.close();
    _allData.clear();
  }
}
