import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'utils.dart';

abstract class SocketServerBase {
  final bool verbose;

  SocketServerBase({this.verbose = false});

  Zone? _zoneGuarded;

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
  Future<bool> start() async {
    if (isStarted) return false;

    final zoneGuarded = _zoneGuarded ??= Zone.current.fork(
        specification:
            ZoneSpecification(handleUncaughtError: _onUncaughtError));

    var server = await zoneGuarded.run(startImpl);
    if (server == null) {
      throw StateError("Can't start server: $this");
    }

    _server = server;

    return true;
  }

  Future<ServerSocket?> startImpl();

  /// Closes the server and stops listening for new connections.
  void close() {
    _server?.close();
    _server = null;
  }

  bool isSocketAddressBlocked(SocketHandlerBase socketHandler);

  void onSocketError(SocketHandlerBase socketHandler);
}

abstract class SocketHandlerBase<S extends SocketServerBase> {
  final Socket socket;
  final DateTime initTime = DateTime.now();

  final S server;

  final int minRequestLength;
  final int maxRequestLength;

  StreamSubscription<Uint8List>? _socketSubscription;

  late final String remoteAddress;
  late final int remotePort;

  SocketHandlerBase(this.socket, this.server,
      {this.minRequestLength = 4, this.maxRequestLength = 1024}) {
    remoteAddress = socket.remoteAddress.address;
    remotePort = socket.remotePort;

    if (server.isSocketAddressBlocked(this)) {
      close();
      logError("Blocked address: $remoteAddress");
    } else {
      _socketSubscription =
          socket.listen(_onData, onError: onError, onDone: _onClose);

      log("Accepted `Socket`");
    }
  }

  void onError(Object error, StackTrace stackTrace) {
    close();
    server.onSocketError(this);
    if (verbose) {
      logError('$error', stackTrace);
    }
  }

  void onInvalidSocketProtocol() {
    close();
    server.onSocketError(this);
    if (verbose) {
      logError('Invalid protocol!');
    }
  }

  void _onClose() {
    close();
    if (verbose) {
      print('-- Closed `Socket`.');
    }
  }

  bool get verbose => server.verbose;

  final List<Uint8List> allData = [];
  int allDataLength = 0;

  void _onData(Uint8List block) async {
    allData.add(block);
    allDataLength += block.length;

    try {
      await processData();
    } catch (e, s) {
      close();
      logError('onData> $e', s);
    }
  }

  Uint8List compactData() {
    if (allData.isEmpty) {
      allDataLength = 0;
      return Uint8List(0);
    } else if (allData.length == 1) {
      var block0 = allData.first;
      allDataLength = block0.length;
      return block0;
    }

    var fullData = allData.reduce((block1, block2) => block1.merge(block2));

    allData.clear();
    allData.add(fullData);
    allDataLength = fullData.length;

    return fullData;
  }

  void removeData(int length) {
    if (allData.isEmpty) {
      return;
    }

    final fullData = compactData();
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

    allData.clear();
    allData.add(rest);
    allDataLength = rest.length;
  }

  Future<void> processData() async {
    if (allDataLength < minRequestLength) {
      return;
    }

    if (allDataLength > maxRequestLength) {
      onInvalidSocketProtocol();
      return;
    }

    final fullData = compactData();

    // print("<${latin1.decode(fullData)}>");

    var idxSpace = fullData.indexOf(32);
    var idxNewLine = fullData.indexOf(10);

    if (idxSpace < 0) {
      if (idxNewLine >= 0) {
        onInvalidSocketProtocol();
      }
      return;
    }

    if (idxSpace <= 1) {
      onInvalidSocketProtocol();
      return;
    }

    if (idxNewLine < 0) {
      return;
    }

    if (idxNewLine < idxSpace) {
      onInvalidSocketProtocol();
      return;
    }

    if (verbose) {
      print('-- processData: <<<${latin1.decode(fullData).trim()}>>>');
    }

    final cmd = latin1.decode(fullData.sublist(0, idxSpace)).trim();
    final args =
        latin1.decode(fullData.sublist(idxSpace + 1, idxNewLine)).trim();

    final processed = await processCommand(cmd, args);

    if (processed == null) {
      allData.clear();
      allDataLength = 0;
      onInvalidSocketProtocol();
    } else if (processed) {
      removeData(idxNewLine + 1);
    }
  }

  Future<bool?> processCommand(String cmd, String args);

  String get logName => '';

  void log(String msg) {
    final now = DateTime.now();
    final time = '$now'.padRight(26, '0');
    final logName = this.logName;
    final colLogName = logName.isNotEmpty ? ' ($logName)' : '';

    print('$time [$remoteAddress:$remotePort]$colLogName $msg');
  }

  void logError(String msg, [StackTrace? stackTrace]) {
    final now = DateTime.now();
    final time = '$now'.padRight(26, '0');
    final logName = this.logName;
    final colLogName = logName.isNotEmpty ? ' ($logName)' : '';

    print('$time [$remoteAddress:$remotePort] [ERROR]$colLogName $msg');

    if (stackTrace != null) {
      print(stackTrace);
    }
  }

  bool get isClosed => _socketSubscription == null;

  void close() {
    final socketSubscription = _socketSubscription;
    _socketSubscription = null;

    try {
      socketSubscription?.cancel();
    } catch (_) {}

    socket.close();
    allData.clear();
    allDataLength = 0;
  }
}

abstract class SocketClientBase {
  /// The host (IP address or hostname) of the server.
  final String host;

  /// The port on which the server is listening.
  final int port;

  final bool verbose;

  /// Creates a new [SocketClient] instance.
  ///
  /// - [host]: The host address of the server.
  /// - [port]: The port number on which the server is listening.
  SocketClientBase(this.host, this.port, {this.verbose = false});

  Socket? _socket;

  String? get remoteAddress => _socket?.remoteAddress.address;
  int? get remotePort => _socket?.remotePort;

  /// A flag indicating whether the client is connected to the server.
  bool get isConnected => _socket != null;

  Uint8List _receivedData = Uint8List(0);

  Completer<Uint8List?>? _waitingData;

  /// Connects to the server.
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

  Future<String?> sendCommand(String command,
      {Duration responseTimeout = const Duration(seconds: 30)}) async {
    final socket = _connectedSocket();

    var waitingData = _waitingData;
    while (waitingData != null) {
      await waitingData.future;
      waitingData = _waitingData;
    }

    waitingData = _waitingData = Completer<Uint8List?>();

    socket.writeln(command);

    var response = await waitingData.future
        .timeout(responseTimeout, onTimeout: () => null);

    if (identical(waitingData, _waitingData)) {
      _waitingData = null;
    }

    String? responseMsg;
    if (response != null) {
      responseMsg = latin1.decode(response);
    }

    return responseMsg;
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
}
