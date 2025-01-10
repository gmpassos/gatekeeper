import 'gatekeeper_base.dart';

/// The [GatekeeperMock] class is a mock implementation of [GatekeeperDriver]
/// used for testing or simulating behaviors without interacting with actual
/// system resources like iptables.
class GatekeeperMock extends GatekeeperDriver {
  final Set<int> blockedPorts;

  GatekeeperMock(this.blockedPorts);

  @override
  Future<String> resolveBinaryPath(String binaryCommand) async {
    return '/bin/$binaryCommand';
  }

  @override
  Future<String?> runCommand(String binaryPath, List<String> args,
      {bool sudo = false, int? expectedExitCode}) async {
    return '';
  }

  @override
  Future<Set<int>> listBlockedTCPPorts(
      {bool sudo = false, Set<int>? allowedPorts}) async {
    return blockedPorts.toSet();
  }

  @override
  Future<bool> blockTCPPort(int port,
      {bool sudo = false,
      required Set<int>? allowedPorts,
      required bool allowAllPorts}) async {
    if (port < 10) {
      throw ArgumentError("Invalid port: $port");
    }

    if (!allowAllPorts &&
        (allowedPorts == null || !allowedPorts.contains(port))) {
      return false;
    }

    blockedPorts.add(port);
    return true;
  }

  @override
  Future<bool> unblockTCPPort(int port,
      {bool sudo = false,
      required Set<int>? allowedPorts,
      required bool allowAllPorts}) async {
    if (port < 10) {
      throw ArgumentError("Invalid port: $port");
    }

    if (!allowAllPorts &&
        (allowedPorts == null || !allowedPorts.contains(port))) {
      return false;
    }

    blockedPorts.remove(port);
    return true;
  }

  @override
  Future<bool> resolve() async => true;

  @override
  String toString() => 'GatekeeperMock{blockedPorts: $blockedPorts}';
}
