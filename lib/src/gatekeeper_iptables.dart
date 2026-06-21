import 'dart:io';

import 'gatekeeper_base.dart';
import 'utils.dart';

/// IPv4 firewall binary.
const String _binIpTables = 'iptables';

/// IPv6 firewall binary.
const String _binIp6Tables = 'ip6tables';

/// Matches an `ACCEPT` rule line and captures the source address.
///
/// Tolerates both `iptables` and `ip6tables -L -n -v` output (the `opt`
/// column shown by `iptables` as `--` is optional, as some `ip6tables`
/// versions omit it).
final RegExp _regExpAcceptAddress =
    RegExp(r'ACCEPT\s+(?:tcp|6|4)\s+(?:--\s+)?\*\s+\*\s+(\S+)');

/// Matches the destination port (`dpt:<port>`) of a rule line.
final RegExp _regExpPort = RegExp(r'dpt:(\d\d+)');

/// The [GatekeeperIpTables] class is a concrete implementation of [GatekeeperDriver]
/// that uses `iptables`/`ip6tables` or a similar utility to manage TCP ports on a system.
///
/// IPv4 rules are managed with `iptables` and IPv6 rules with `ip6tables`.
/// The correct binary is selected from the address family for address-based
/// operations ([acceptAddressOnTCPPort]/[unacceptAddressOnTCPPort]), while
/// port-based operations ([blockTCPPort]/[unblockTCPPort]) and listings span
/// both families. `ip6tables` is optional: when it is not installed, IPv6
/// operations are skipped gracefully.
///
/// Example usage:
/// ```dart
/// var gatekeeper = GatekeeperIpTables();
/// await gatekeeper.listBlockedTCPPorts();
/// await gatekeeper.blockTCPPort(8080);
/// ```
class GatekeeperIpTables extends GatekeeperDriver {
  final bool verbose;

  GatekeeperIpTables({this.verbose = false});

  @override
  Future<String> resolveBinaryPath(String binaryCommand) async {
    try {
      final result = await Process.run('which', [binaryCommand]);

      if (result.exitCode == 0) {
        var stdout = result.stdout as String;
        return stdout.trim();
      } else {
        throw Exception('Command not found: $binaryCommand');
      }
    } catch (e) {
      throw Exception('Failed to resolve binary path: $e');
    }
  }

  /// Resolves [binaryCommand] like [resolveBinaryPathCached], but returns
  /// `null` instead of throwing when the binary is not available. Used for the
  /// optional `ip6tables` binary.
  Future<String?> _resolveBinaryPathOrNull(String binaryCommand) async {
    try {
      var path = await resolveBinaryPathCached(binaryCommand);
      return path.isNotEmpty ? path : null;
    } catch (_) {
      return null;
    }
  }

  /// Returns the firewall binary path for the given [address] family
  /// (`ip6tables` for IPv6, `iptables` otherwise), or `null` if that binary is
  /// not available on this system.
  Future<String?> _resolveBinaryPathForAddress(String address) =>
      _resolveBinaryPathOrNull(
          isIPv6Address(address) ? _binIp6Tables : _binIpTables);

  /// Returns the available firewall binary paths: `iptables` (required) plus
  /// `ip6tables` when installed. Throws if `iptables` is missing.
  Future<List<String>> _resolveFirewallBinaries() async {
    final bins = <String>[];

    final ipTables = await resolveBinaryPathCached(_binIpTables);
    if (ipTables.isNotEmpty) bins.add(ipTables);

    final ip6Tables = await _resolveBinaryPathOrNull(_binIp6Tables);
    if (ip6Tables != null) bins.add(ip6Tables);

    return bins;
  }

  @override
  Future<String?> runCommand(String binaryPath, List<String> args,
      {bool sudo = false, int? expectedExitCode}) async {
    if (verbose) {
      print('-- RUN> ${sudo ? 'sudo ' : ''}$binaryPath ${args.join(' ')}');
    }

    final result = sudo
        ? await Process.run('sudo', [binaryPath, ...args])
        : await Process.run(binaryPath, args);

    if (verbose) {
      print('-- exitCode: ${result.exitCode}');
    }

    if (expectedExitCode != null && result.exitCode != expectedExitCode) {
      return null;
    }

    final output = result.stdout as String? ?? '';

    if (verbose) {
      print('<<<\n$output>>>');
    }

    return output;
  }

  @override
  Future<Set<int>> listBlockedTCPPorts(
      {bool sudo = false, Set<int>? allowedPorts}) async {
    final bins = await _resolveFirewallBinaries();

    final blockedPorts = <int>{};

    for (final bin in bins) {
      var output = await runCommand(
        bin,
        <String>['-L', 'INPUT', '-n', '-v'],
        sudo: sudo,
        expectedExitCode: 0,
      );

      if (output == null || output.isEmpty) continue;

      for (final line in output.split('\n')) {
        if (line.contains('DROP') || line.contains('REJECT')) {
          final match = _regExpPort.firstMatch(line);
          if (match != null) {
            var g1 = match.group(1)!;
            var p = int.tryParse(g1.trim());
            if (p != null && p >= 10) {
              blockedPorts.add(p);
            }
          }
        }
      }
    }

    if (allowedPorts != null) {
      blockedPorts.retainAll(allowedPorts);
    }

    return blockedPorts;
  }

  @override
  Future<bool> blockTCPPort(int port,
      {bool sudo = false,
      required Set<int>? allowedPorts,
      required bool allowAllPorts}) async {
    _checkValidPort(port);

    if (!allowAllPorts &&
        (allowedPorts == null || !allowedPorts.contains(port))) {
      return false;
    }

    // Block on every available family so the port is actually closed for both
    // IPv4 and IPv6 traffic.
    final bins = await _resolveFirewallBinaries();

    var allOk = true;
    for (final bin in bins) {
      var output = await runCommand(
        bin,
        <String>['-A', 'INPUT', '-p', 'tcp', '--dport', '$port', '-j', 'DROP'],
        sudo: sudo,
        expectedExitCode: 0,
      );

      if (output == null) allOk = false;
    }

    if (!allOk) {
      return false;
    }

    var blocked = await isBlockedTCPPort(port,
        sudo: sudo, allowedPorts: allowAllPorts ? null : (allowedPorts ?? {}));
    return blocked;
  }

  @override
  Future<bool> unblockTCPPort(int port,
      {bool sudo = false,
      required Set<int>? allowedPorts,
      required bool allowAllPorts}) async {
    _checkValidPort(port);

    if (!allowAllPorts &&
        (allowedPorts == null || !allowedPorts.contains(port))) {
      return false;
    }

    final bins = await _resolveFirewallBinaries();

    var allOk = true;
    for (final bin in bins) {
      var output = await runCommand(
        bin,
        <String>['-D', 'INPUT', '-p', 'tcp', '--dport', '$port', '-j', 'DROP'],
        sudo: sudo,
        expectedExitCode: 0,
      );

      if (output == null) allOk = false;
    }

    if (!allOk) {
      return false;
    }

    var blocked = await isBlockedTCPPort(port,
        sudo: sudo, allowedPorts: allowAllPorts ? null : (allowedPorts ?? {}));
    return !blocked;
  }

  @override
  Future<Set<(String, int)>> listAcceptedAddressesOnTCPPorts(
      {bool sudo = false, Set<int>? allowedPorts}) async {
    final bins = await _resolveFirewallBinaries();

    final accepts = <(String, int)>{};

    for (final bin in bins) {
      var output = await runCommand(
        bin,
        <String>['-L', 'INPUT', '-n', '-v'],
        sudo: sudo,
        expectedExitCode: 0,
      );

      if (output == null || output.isEmpty) continue;

      for (final line in output.split('\n')) {
        if (line.contains('ACCEPT')) {
          final matchAddress = _regExpAcceptAddress.firstMatch(line);
          final matchPort = _regExpPort.firstMatch(line);
          if (matchAddress != null && matchPort != null) {
            var address = normalizeIpAddress(matchAddress.group(1)!);
            var gPort = matchPort.group(1)!;
            var port = int.tryParse(gPort.trim());
            if (address.isNotEmpty && port != null && port >= 10) {
              accepts.add((address, port));
            }
          }
        }
      }
    }

    if (allowedPorts != null) {
      accepts.removeWhere((e) => !allowedPorts.contains(e.$2));
    }

    return accepts;
  }

  @override
  Future<bool> acceptAddressOnTCPPort(String address, int port,
      {bool sudo = false,
      required Set<int>? allowedPorts,
      required bool allowAllPorts}) async {
    _checkValidPort(port);
    address = _checkAddress(address);

    if (!allowAllPorts &&
        (allowedPorts == null || !allowedPorts.contains(port))) {
      return false;
    }

    // Select `iptables` or `ip6tables` from the address family.
    final bin = await _resolveBinaryPathForAddress(address);
    if (bin == null) {
      // IPv6 address requested but `ip6tables` is not available.
      return false;
    }

    var output = await runCommand(
      bin,
      <String>[
        '-I',
        'INPUT',
        '-p',
        'tcp',
        '--dport',
        '$port',
        '-s',
        address,
        '-j',
        'ACCEPT',
      ],
      sudo: sudo,
      expectedExitCode: 0,
    );

    if (output == null) {
      return false;
    }

    var accepted = await isAcceptedAddressOnPort(address, port,
        sudo: sudo, allowedPorts: allowAllPorts ? null : (allowedPorts ?? {}));

    return accepted;
  }

  @override
  Future<bool> unacceptAddressOnTCPPort(String address, int? port,
      {bool sudo = false,
      required Set<int>? allowedPorts,
      required bool allowAllPorts}) async {
    address = _checkAddress(address);

    // The address family determines which firewall table holds the rule.
    final bin = await _resolveBinaryPathForAddress(address);
    if (bin == null) {
      return false;
    }

    var output = await runCommand(
      bin,
      <String>['-L', 'INPUT', '-n', '-v', '--line-numbers'],
      sudo: sudo,
      expectedExitCode: 0,
    );

    if (output == null || output.isEmpty) return false;

    var anyCmdOK = false;

    // Iterate in reverse so deleting a rule by line number does not shift the
    // numbers of rules still pending deletion.
    final lines = output.split('\n').reversed;

    for (final line in lines) {
      if (line.contains('ACCEPT')) {
        final matchAddress = _regExpAcceptAddress.firstMatch(line);
        final matchPort = _regExpPort.firstMatch(line);
        if (matchAddress != null && matchPort != null) {
          var a = normalizeIpAddress(matchAddress.group(1)!);
          var g1 = matchPort.group(1)!;
          var p = int.tryParse(g1.trim());

          if (a == address && p != null && (port == null || p == port)) {
            var lineN = line.trim().split(RegExp(r'\s+'))[0];
            var n = int.tryParse(lineN);

            if (n != null && n > 0) {
              final iptablesDelArgs = <String>['-D', 'INPUT', '$n'];

              var output = await runCommand(
                bin,
                iptablesDelArgs,
                sudo: sudo,
                expectedExitCode: 0,
              );

              var cmdOk = output != null;
              if (cmdOk) {
                anyCmdOK = true;
              }
            }
          }
        }
      }
    }

    if (!anyCmdOK) return false;

    bool accepted;
    if (port != null) {
      accepted = await isAcceptedAddressOnPort(address, port,
          sudo: sudo,
          allowedPorts: allowAllPorts ? null : (allowedPorts ?? {}));
    } else {
      accepted = await isAcceptedAddress(address,
          sudo: sudo,
          allowedPorts: allowAllPorts ? null : (allowedPorts ?? {}));
    }

    return !accepted;
  }

  @override
  Future<bool> resolve() async {
    final iptablesBin = await resolveBinaryPathCached(_binIpTables);
    return iptablesBin.isNotEmpty;
  }

  @override
  String toString() => 'GatekeeperIpTables{}';
}

void _checkValidPort(int port) {
  if (!_isValidPort(port)) {
    throw ArgumentError("Invalid port: $port");
  }
}

bool _isValidPort(int port) => port >= 10 && port <= 65535;

String _checkAddress(String address) {
  var address2 = _normalizeAddress(address);
  if (address2 == null) {
    throw ArgumentError("Invalid address: $address");
  }
  return address2;
}

String? _normalizeAddress(String? address) {
  if (address == null) return null;
  // Collapse IPv4-mapped IPv6 (`::ffff:1.2.3.4`) to plain IPv4 so it targets
  // the IPv4 table.
  address = normalizeIpAddress(address);
  if (address.isEmpty) return null;

  // If has any invalid character:
  if (RegExp(r'[^0-9a-fA-F:.]').hasMatch(address)) {
    return null;
  }

  if (address.contains('..')) {
    return null;
  }

  return address;
}
