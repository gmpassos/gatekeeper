import 'dart:async';
import 'dart:io';

import 'gatekeeper_base.dart';
import 'socket_base.dart';

class GateKeeperIRPCServer extends SocketServerBase {
  final Gatekeeper gatekeeper;

  final int listenPort;

  GateKeeperIRPCServer(this.gatekeeper,
      {this.listenPort = 7127, super.verbose = false});

  /// Starts the server and begins listening for incoming local connections.
  ///
  /// Returns a [Future] that completes with `true` if the server successfully starts,
  /// or `false` if it is already running.
  ///
  /// Throws a [StateError] if the [GateKeeperIRPC] cannot resolve.
  @override
  Future<bool> start() async {
    if (isStarted) return false;
    return super.start();
  }

  @override
  Future<ServerSocket> startImpl() async {
    var server =
        await ServerSocket.bind(InternetAddress.loopbackIPv4, listenPort);
    server.listen(_onAcceptSocket);
    return server;
  }

  void _onAcceptSocket(Socket socket) {
    _SocketHandler(socket, this);
  }

  @override
  bool isSocketAddressBlocked(
          SocketHandlerBase<SocketServerBase> socketHandler) =>
      false;

  @override
  void onSocketError(SocketHandlerBase<SocketServerBase> socketHandler) {}
}

class _SocketHandler extends SocketHandlerBase<GateKeeperIRPCServer> {
  _SocketHandler(super.socket, super.server) : super(maxRequestLength: 512);

  Gatekeeper get gatekeeper => server.gatekeeper;

  @override
  String get logName => 'IRPC';

  void _sendResponse(String message) {
    if (verbose) {
      print('-- sendResponse: <<<$message>>>');
    }

    socket.writeln(message);
  }

  @override
  Future<bool?> processCommand(String cmd, String args) async {
    switch (cmd) {
      case 'block_ip':
        {
          var ip = args.trim();

          if (ip.length >= 7) {
            var ok = await gatekeeper.blockIP(ip);
            _sendResponse("block_ip: $ok");

            log('BLOCKED IP: $ip');

            return true;
          } else {
            close();
            return null;
          }
        }

      case 'unblock_ip':
        {
          var ip = args.trim();

          if (ip.length >= 7) {
            var ok = await gatekeeper.unblockIP(ip);
            _sendResponse("unblock_ip: $ok");

            log('UNBLOCKED IP: $ip');

            return true;
          } else {
            close();
            return null;
          }
        }

      case 'disconnect':
        {
          _sendResponse("disconnect: true");
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
}
