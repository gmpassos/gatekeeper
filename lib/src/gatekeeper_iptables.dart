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
  Future<Set<String>> listBlockedIPs({bool sudo = false}) async {
    final iptablesBin = await resolveBinaryPathCached('iptables');
    final iptablesArgs = <String>['-L', 'INPUT', '-n', '-v'];

    var output = await runCommand(
      iptablesBin,
      iptablesArgs,
      sudo: sudo,
      expectedExitCode: 0,
    );

    if (output == null || output.isEmpty) return {};

    final regExpIP = RegExp(r'('
        r'(?:\d{1,3}\.){3}\d{1,3}'
        r'|'
        r'([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}'
        r')\b');

    final blockedIPs = <String>{};

    for (final line in output.split('\n')) {
      // Only DROP/REJECT lines without "dpt:" (port-specific)
      if ((line.contains('DROP') || line.contains('REJECT')) &&
          !line.contains('dpt:')) {
        final match = regExpIP.firstMatch(line);
        if (match != null) {
          blockedIPs.add(match.group(0)!);
        }
      }
    }

    return blockedIPs;
  }

  static final _regexpIP = RegExp(
      r'^((?:\d{1,3}\.){3}\d{1,3}|([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4})$');

  @override
  Future<bool> blockIP(String ip, {bool sudo = false}) async {
    if (!_regexpIP.hasMatch(ip)) {
      throw ArgumentError('Invalid IP address: $ip');
    }

    final iptablesBin = await resolveBinaryPathCached('iptables');
    final iptablesArgs = <String>[
      '-A',
      'INPUT',
      '-s',
      ip,
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

    var blockedIPs = await listBlockedIPs(sudo: sudo);
    return blockedIPs.contains(ip);
  }

  @override
  Future<bool> unblockIP(String ip, {bool sudo = false}) async {
    if (!_regexpIP.hasMatch(ip)) {
      throw ArgumentError('Invalid IP address: $ip');
    }

    final iptablesBin = await resolveBinaryPathCached('iptables');
    final iptablesArgs = <String>[
      '-D',
      'INPUT',
      '-s',
      ip,
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

    var blockedIPs = await listBlockedIPs(sudo: sudo);
    return !blockedIPs.contains(ip);
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
    _checkValidPort(port);

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
    _checkValidPort(port);

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
  Future<Set<(String, int)>> listAcceptedAddressesOnTCPPorts(
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

    final regExpAddress =
        RegExp(r'ACCEPT\s+(?:tcp|6|4)\s+--\s+\*\s+\*\s+(\S+)');
    final regExpPort = RegExp(r'dpt:(\d\d+)');

    final accepts = <(String, int)>{};

    for (final line in output.split('\n')) {
      if (line.contains('ACCEPT')) {
        final matchAddress = regExpAddress.firstMatch(line);
        final matchPort = regExpPort.firstMatch(line);
        if (matchAddress != null && matchPort != null) {
          var address = matchAddress.group(1)!;
          var gPort = matchPort.group(1)!;
          var port = int.tryParse(gPort.trim());
          if (address.isNotEmpty && port != null && port >= 10) {
            accepts.add((address, port));
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

    final iptablesBin = await resolveBinaryPathCached('iptables');
    final iptablesArgs = <String>[
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

    final iptablesBin = await resolveBinaryPathCached('iptables');
    final iptablesArgs = <String>['-L', 'INPUT', '-n', '-v', '--line-numbers'];

    var output = await runCommand(
      iptablesBin,
      iptablesArgs,
      sudo: sudo,
      expectedExitCode: 0,
    );

    if (output == null || output.isEmpty) return false;

    final regExpAddress =
        RegExp(r'ACCEPT\s+(?:tcp|6|4)\s+--\s+\*\s+\*\s+(\S+)');
    final regExpPort = RegExp(r'dpt:(\d\d+)');

    var anyCmdOK = false;

    for (final line in output.split('\n')) {
      if (line.contains('ACCEPT')) {
        final matchAddress = regExpAddress.firstMatch(line);
        final matchPort = regExpPort.firstMatch(line);
        if (matchAddress != null && matchPort != null) {
          var a = matchAddress.group(1)!;
          var g1 = matchPort.group(1)!;
          var p = int.tryParse(g1.trim());

          if (a == address && p != null && (port == null || p == port)) {
            var lineN = line.trim().split(RegExp(r'\s+'))[0];
            var n = int.tryParse(lineN);

            if (n != null && n > 0) {
              final iptablesDelArgs = <String>['-D', 'INPUT', '$n'];

              var output = await runCommand(
                iptablesBin,
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
    final iptablesBin = await resolveBinaryPathCached('iptables');
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
  address = address.trim();
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
