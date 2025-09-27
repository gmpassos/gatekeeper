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
import 'gatekeeper_ipc_server.dart';
import 'socket_base.dart';

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
class GatekeeperServer extends SocketServerBase {
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

  /// The IPC server (optional).
  /// See `ipcPort` on [GatekeeperServer] constructor.
  late final GateKeeperIPCServer? ipcServer;

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
      int? ipcPort,
      bool? ipc,
      super.verbose = false})
      : address = address ?? InternetAddress.anyIPv4,
        loginErrorLimit = normalizeLoginErrorLimit(loginErrorLimit),
        blockingTime = normalizeBlockingTime(blockingTime) {
    if (accessKey.length < 32) {
      throw ArgumentError(
          "Invalid `accessKey` length: ${accessKey.length} < 32");
    }

    ipc ??= ipcPort != null && ipcPort > 0;

    ipcServer = ipc
        ? GateKeeperIPCServer(
            gatekeeper,
            listenPort: ipcPort,
            verbose: verbose,
          )
        : null;

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

  /// Starts the server and begins listening for incoming connections.
  ///
  /// Returns a [Future] that completes with `true` if the server successfully starts,
  /// or `false` if it is already running.
  ///
  /// Throws a [StateError] if the [Gatekeeper] cannot resolve.
  @override
  Future<bool> start() async {
    var started = await super.start();
    if (!started) return false;

    var ok = await gatekeeper.resolve();
    if (!ok) {
      throw StateError("Can't resolve `Gatekeeper`");
    }

    final ipcServer = this.ipcServer;
    if (ipcServer != null) {
      var ipcOk = await ipcServer.start();
      if (!ipcOk) {
        close();
        throw StateError("Can't start IPC server: $ipcServer");
      }
    }

    return true;
  }

  @override
  Future<ServerSocket> startImpl() async {
    var server = await ServerSocket.bind(address, listenPort);
    server.listen(_onAcceptSocket);
    return server;
  }

  @override
  void close() {
    super.close();
    ipcServer?.close();
  }

  late final AESEncryptor _aesEncryptor = AESEncryptor(accessKey);

  void _onAcceptSocket(Socket socket) {
    _SocketHandler(socket, this);
  }

  final Map<String, DateTime> _loginErrorLimit = {};

  @override
  bool isSocketAddressBlocked(SocketHandlerBase socketHandler) {
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
    print('-- `Socket` $remoteAddress: login error limit!');
  }

  final Map<String, (int, DateTime)> _socketError = {};

  @override
  void onSocketError(SocketHandlerBase socketHandler) {
    var remoteAddress = socketHandler.remoteAddress;

    if (remoteAddress == '127.0.0.1' ||
        remoteAddress == '::1' ||
        remoteAddress == 'localhost') {
      print('-- Ignore local `Socket` $remoteAddress error count.');
      return;
    }

    var prev = _socketError[remoteAddress];

    final now = DateTime.now();

    int prevCount;
    if (prev != null) {
      var elapsedTime = now.difference(prev.$2);
      prevCount = elapsedTime > blockingTime ? 0 : prev.$1;
    } else {
      prevCount = 0;
    }

    prev = _socketError[remoteAddress] = (prevCount + 1, now);

    print('-- `Socket` $remoteAddress error count: $prev');
  }

  @override
  String toString() =>
      'GatekeeperServer[${Gatekeeper.VERSION}]{listenPort: $listenPort, address: $address}@$gatekeeper';
}

class _SocketHandler extends SocketHandlerBase<GatekeeperServer> {
  _SocketHandler(super.socket, super.server) {
    if (!isClosed) {
      Future.delayed(Duration(seconds: 30), _checkLogged);
    }
  }

  void _checkLogged() {
    if (!_logged && !isClosed) {
      close();
      server.onSocketError(this);
      logError('Login timeout!');
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

  @override
  Future<bool?> processCommand(String cmd, String args) async {
    var secure = false;
    if (cmd.startsWith('_:')) {
      String msg;

      try {
        msg = chainAESEncryptor.decryptMessage(args);
      } catch (e, s) {
        logError('Invalid encryption key while decrypting message!', s);
        return false;
      }

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

            log('LOGIN');

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

            log('List ports.');

            return true;
          } else if (args == 'accepts') {
            var acceptedAddresses =
                await gatekeeper.listAcceptedAddressesOnTCPPorts();

            var response = acceptedAddresses
                .map((e) => '${e.address}:${e.port}')
                .join('; ');

            _sendResponse(response, secure: secure);

            log('List accepted addresses.');

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

            log('BLOCKED PORT: $port');

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

            log('UNBLOCKED PORT: $port');

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

            log('ACCEPTED: $address -> $port');

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

            log('UNACCEPTED: $address -> $port');

            return true;
          } else {
            close();
            return null;
          }
        }

      case 'myip':
        {
          var ip = remoteAddress;
          _sendResponse("ip: $ip", secure: secure);

          log('IP: $ip');

          return true;
        }

      case 'disconnect':
        {
          _sendResponse("disconnect: true", secure: secure);
          socket.close();

          log('DISCONNECT');

          return true;
        }

      default:
        {
          close();

          log('CLOSE - Unknown command: $cmd');

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

    log('SESSION');

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
}
