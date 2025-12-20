import 'socket_base.dart';

class GatekeeperIPCClient extends SocketClientBase {
  GatekeeperIPCClient({int? port}) : super('localhost', port ?? 7127);

  Future<List<String>> listBlockedIPs() async {
    var response = await sendCommand('list blocked_ips');
    if (response == null || response.isEmpty) return [];

    response = response.split(':')[1].trim();

    var ips = response
        .split('; ')
        .map((ip) => ip.trim())
        .where((ip) => ip.isNotEmpty)
        .toList();

    return ips;
  }

  Future<bool> blockIP(String ip) async {
    var response = await sendCommand('block_ip $ip');
    var ok = response?.contains('block_ip: true') ?? false;
    return ok;
  }

  Future<bool> unblockIP(String ip) async {
    var response = await sendCommand('unblock_ip $ip');
    var ok = response?.contains('unblock_ip: true') ?? false;
    return ok;
  }

  Future<bool> disconnect() async {
    var response = await sendCommand("disconnect socket");
    return response?.contains('true') ?? false;
  }

  @override
  String toString() => 'GatekeeperIPCClient@$host:$port';
}
