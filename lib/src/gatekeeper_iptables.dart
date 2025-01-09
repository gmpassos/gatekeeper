import 'dart:io';

import 'gatekeeper_base.dart';

/// The [GatekeeperIpTables] class is a concrete implementation of [GatekeeperDriver]
/// that uses `iptables` or a similar utility to manage TCP ports on a system.
///
/// Example usage:
/// ```dart
/// var gatekeeper = GatekeeperIpTables();
/// await gatekeeper.listBlockedTCPPorts();
/// await gatekeeper.blockTCPPort(8080);
/// ```
class GatekeeperIpTables extends GatekeeperDriver {
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

  @override
  Future<String?> runCommand(String binaryPath, List<String> args,
      {bool sudo = false, int? expectedExitCode}) async {
    final result = sudo
        ? await Process.run('sudo', [binaryPath, ...args])
        : await Process.run(binaryPath, args);

    if (expectedExitCode != null && result.exitCode != expectedExitCode) {
      return null;
    }

    final output = result.stdout as String? ?? '';
    return output;
  }

  @override
  Future<Set<int>> listBlockedTCPPorts(
      {bool sudo = false, Set<int>? allowedPorts}) async {
    final iptablesBin = await resolveBinaryPathCached('iptables');
    final iptablesArgs = <String>['-L', 'INPUT', '-n', '-v'];

    var output = await runCommand(
      iptablesBin,
      iptablesArgs,
      sudo: sudo,
      expectedExitCode: 0,
    );

    if (output == null || output.isEmpty) return {};

    final regExpPort = RegExp(r'dpt:(\d\d+)');

    final blockedPorts = <int>{};

    for (final line in output.split('\n')) {
      if (line.contains('DROP') || line.contains('REJECT')) {
        final match = regExpPort.firstMatch(line);
        if (match != null) {
          var g1 = match.group(1)!;
          var p = int.tryParse(g1.trim());
          if (p != null && p >= 10) {
            blockedPorts.add(p);
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
    if (port < 10) {
      throw ArgumentError("Invalid port: $port");
    }

    if (!allowAllPorts &&
        (allowedPorts == null || !allowedPorts.contains(port))) {
      return false;
    }

    final iptablesBin = await resolveBinaryPathCached('iptables');
    final iptablesArgs = <String>[
      '-A',
      'INPUT',
      '-p',
      'tcp',
      '--dport',
      '$port',
      '-j',
      'DROP',
    ];

    var output = await runCommand(
      iptablesBin,
      iptablesArgs,
      sudo: sudo,
      expectedExitCode: 0,
    );

    if (output == null) {
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
    if (port < 10) {
      throw ArgumentError("Invalid port: $port");
    }

    if (!allowAllPorts &&
        (allowedPorts == null || !allowedPorts.contains(port))) {
      return false;
    }

    final iptablesBin = await resolveBinaryPathCached('iptables');
    final iptablesArgs = <String>[
      '-D',
      'INPUT',
      '-p',
      'tcp',
      '--dport',
      '$port',
      '-j',
      'DROP',
    ];

    var output = await runCommand(
      iptablesBin,
      iptablesArgs,
      sudo: sudo,
      expectedExitCode: 0,
    );

    if (output == null) {
      return false;
    }

    var blocked = await isBlockedTCPPort(port,
        sudo: sudo, allowedPorts: allowAllPorts ? null : (allowedPorts ?? {}));
    return !blocked;
  }

  @override
  Future<bool> resolve() async {
    final iptablesBin = await resolveBinaryPathCached('iptables');
    return iptablesBin.isNotEmpty;
  }

  @override
  String toString() => 'GatekeeperIpTables{}';
}
