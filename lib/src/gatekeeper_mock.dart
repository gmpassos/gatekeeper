import 'gatekeeper_base.dart';

/// The [GatekeeperMock] class is a mock implementation of [GatekeeperDriver]
/// used for testing or simulating behaviors without interacting with actual
/// system resources like iptables.
class GatekeeperMock extends GatekeeperDriver {
  final Set<int> blockedPorts;
  final Set<(String, int)> acceptedAddressesOnPort;

  GatekeeperMock(
      {Set<int>? blockedPorts, Set<(String, int)>? acceptedAddressesOnPort})
      : blockedPorts = blockedPorts ?? {},
        acceptedAddressesOnPort = acceptedAddressesOnPort ?? {};

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
    var set = blockedPorts.toSet();

    if (allowedPorts != null) {
      set.removeWhere((p) => !allowedPorts.contains(p));
    }

    return set;
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
  Future<Set<(String, int)>> listAcceptedAddressesOnTCPPorts(
      {bool sudo = false, Set<int>? allowedPorts}) async {
    var set = acceptedAddressesOnPort.toSet();

    if (allowedPorts != null) {
      set.removeWhere((e) => !allowedPorts.contains(e.$2));
    }

    return set;
  }

  @override
  Future<bool> acceptAddressOnTCPPort(String address, int port,
      {bool sudo = false,
      required Set<int>? allowedPorts,
      required bool allowAllPorts}) async {
    if (!allowAllPorts &&
        (allowedPorts == null || !allowedPorts.contains(port))) {
      return false;
    }

    acceptedAddressesOnPort.add((address, port));
    return true;
  }

  @override
  Future<bool> unacceptAddressOnTCPPort(String address, int? port,
      {bool sudo = false,
      required Set<int>? allowedPorts,
      required bool allowAllPorts}) async {
    if (port != null &&
        !allowAllPorts &&
        (allowedPorts == null || !allowedPorts.contains(port))) {
      return false;
    }

    if (port != null) {
      acceptedAddressesOnPort.remove((address, port));
    } else {
      acceptedAddressesOnPort.removeWhere((e) => e.$1 == address);
    }
    return true;
  }

  @override
  Future<bool> resolve() async => true;

  @override
  String toString() => 'GatekeeperMock{blockedPorts: $blockedPorts}';
}
