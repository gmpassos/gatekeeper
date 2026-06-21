import 'package:gatekeeper/gatekeeper_iptables.dart';
import 'package:test/test.dart';

/// A single emulated firewall rule.
class _Rule {
  final String target; // DROP | ACCEPT
  final int port;
  final String source; // `0.0.0.0/0` for DROP, an address for ACCEPT

  _Rule(this.target, this.port, this.source);
}

/// A [GatekeeperIpTables] whose binary resolution and command execution are
/// emulated in-memory, so the real `-L` output parsing and rule-management
/// logic of the driver can be exercised without `iptables`/`ip6tables`
/// installed.
class _FakeIpTables extends GatekeeperIpTables {
  final bool hasIp6tables;

  /// Emulated rule tables keyed by binary name (`iptables` / `ip6tables`).
  final Map<String, List<_Rule>> _tables = {
    'iptables': [],
    'ip6tables': [],
  };

  final List<String> runLog = [];

  _FakeIpTables({this.hasIp6tables = true});

  String _binName(String binaryPath) =>
      binaryPath.split('/').last; // `/sbin/iptables` -> `iptables`

  @override
  Future<String> resolveBinaryPath(String binaryCommand) async {
    if (binaryCommand == 'ip6tables' && !hasIp6tables) {
      throw Exception('Command not found: ip6tables');
    }
    return '/sbin/$binaryCommand';
  }

  @override
  Future<String?> runCommand(String binaryPath, List<String> args,
      {bool sudo = false, int? expectedExitCode}) async {
    runLog.add('$binaryPath ${args.join(' ')}');

    final rules = _tables[_binName(binaryPath)]!;

    // Listing: `-L INPUT -n -v [--line-numbers]`
    if (args.isNotEmpty && args[0] == '-L') {
      final withLineNumbers = args.contains('--line-numbers');
      return _renderListing(rules, withLineNumbers: withLineNumbers);
    }

    // Delete by line number: `-D INPUT <n>`
    if (args.length == 3 && args[0] == '-D' && args[1] == 'INPUT') {
      final n = int.tryParse(args[2]);
      if (n != null && n >= 1 && n <= rules.length) {
        rules.removeAt(n - 1);
        return '';
      }
      return null;
    }

    // Rule mutation: `-A|-I|-D INPUT -p tcp --dport <port> [-s <addr>] -j <T>`
    final op = args[0];
    final port = _argValue(args, '--dport');
    final target = _argValue(args, '-j');
    final source = _argValue(args, '-s') ?? '0.0.0.0/0';

    if (port == null || target == null) return null;
    final portN = int.parse(port);

    if (op == '-A') {
      rules.add(_Rule(target, portN, source));
      return '';
    } else if (op == '-I') {
      rules.insert(0, _Rule(target, portN, source));
      return '';
    } else if (op == '-D') {
      final idx = rules.indexWhere((r) =>
          r.target == target && r.port == portN && r.source == source);
      if (idx >= 0) {
        rules.removeAt(idx);
        return '';
      }
      return null;
    }

    return null;
  }

  String? _argValue(List<String> args, String flag) {
    final i = args.indexOf(flag);
    if (i < 0 || i + 1 >= args.length) return null;
    return args[i + 1];
  }

  String _renderListing(List<_Rule> rules, {required bool withLineNumbers}) {
    final buf = StringBuffer();
    buf.writeln('Chain INPUT (policy ACCEPT 0 packets, 0 bytes)');
    buf.writeln('${withLineNumbers ? 'num  ' : ''}'
        ' pkts bytes target     prot opt in     out     source               destination');
    for (var i = 0; i < rules.length; i++) {
      final r = rules[i];
      final prefix = withLineNumbers ? '${i + 1}    ' : '';
      buf.writeln('$prefix    0     0 ${r.target.padRight(10)} tcp  --  '
          '*      *       ${r.source.padRight(20)} 0.0.0.0/0            tcp dpt:${r.port}');
    }
    return buf.toString();
  }
}

void main() {
  group('GatekeeperIpTables (emulated firewall)', () {
    test('resolve requires iptables', () async {
      expect(await _FakeIpTables().resolve(), isTrue);
    });

    test('block / list / unblock spans both families', () async {
      final fw = _FakeIpTables();

      expect(
          await fw.listBlockedTCPPorts(allowedPorts: null), equals(<int>{}));

      expect(
          await fw.blockTCPPort(2223,
              allowedPorts: null, allowAllPorts: true),
          isTrue);
      expect(await fw.listBlockedTCPPorts(allowedPorts: null), equals({2223}));

      // Applied to BOTH iptables and ip6tables.
      expect(fw._tables['iptables']!.any((r) => r.port == 2223), isTrue);
      expect(fw._tables['ip6tables']!.any((r) => r.port == 2223), isTrue);

      expect(
          await fw.unblockTCPPort(2223,
              allowedPorts: null, allowAllPorts: true),
          isTrue);
      expect(
          await fw.listBlockedTCPPorts(allowedPorts: null), equals(<int>{}));
    });

    test('accept IPv4 uses iptables, IPv6 uses ip6tables', () async {
      final fw = _FakeIpTables();

      expect(
          await fw.acceptAddressOnTCPPort('1.2.3.4', 2223,
              allowedPorts: null, allowAllPorts: true),
          isTrue);
      expect(
          await fw.acceptAddressOnTCPPort('2001:db8::1', 2223,
              allowedPorts: null, allowAllPorts: true),
          isTrue);

      // Routed to the correct table by family.
      expect(fw._tables['iptables']!.map((r) => r.source), contains('1.2.3.4'));
      expect(fw._tables['ip6tables']!.map((r) => r.source),
          contains('2001:db8::1'));

      expect(
          await fw.listAcceptedAddressesOnTCPPorts(allowedPorts: null),
          equals(<(String, int)>{
            ('1.2.3.4', 2223),
            ('2001:db8::1', 2223),
          }));
    });

    test('IPv4-mapped IPv6 is accepted as IPv4', () async {
      final fw = _FakeIpTables();

      expect(
          await fw.acceptAddressOnTCPPort('::ffff:1.2.3.4', 2223,
              allowedPorts: null, allowAllPorts: true),
          isTrue);

      expect(fw._tables['iptables']!.map((r) => r.source), contains('1.2.3.4'));
      expect(fw._tables['ip6tables'], isEmpty);
    });

    test('unaccept removes the rule from its family table', () async {
      final fw = _FakeIpTables();

      await fw.acceptAddressOnTCPPort('2001:db8::1', 2223,
          allowedPorts: null, allowAllPorts: true);
      await fw.acceptAddressOnTCPPort('2001:db8::1', 2224,
          allowedPorts: null, allowAllPorts: true);

      // Remove a single port.
      expect(
          await fw.unacceptAddressOnTCPPort('2001:db8::1', 2223,
              allowedPorts: null, allowAllPorts: true),
          isTrue);
      expect(
          await fw.listAcceptedAddressesOnTCPPorts(allowedPorts: null),
          equals(<(String, int)>{('2001:db8::1', 2224)}));

      // Remove from all ports (port == null).
      await fw.acceptAddressOnTCPPort('2001:db8::1', 2225,
          allowedPorts: null, allowAllPorts: true);
      expect(
          await fw.unacceptAddressOnTCPPort('2001:db8::1', null,
              allowedPorts: null, allowAllPorts: true),
          isTrue);
      expect(await fw.listAcceptedAddressesOnTCPPorts(allowedPorts: null),
          equals(<(String, int)>{}));
    });

    test('IPv6 accept returns false when ip6tables is unavailable', () async {
      final fw = _FakeIpTables(hasIp6tables: false);

      expect(
          await fw.acceptAddressOnTCPPort('2001:db8::1', 2223,
              allowedPorts: null, allowAllPorts: true),
          isFalse);

      // IPv4 still works.
      expect(
          await fw.acceptAddressOnTCPPort('1.2.3.4', 2223,
              allowedPorts: null, allowAllPorts: true),
          isTrue);
    });

    test('allowedPorts is enforced', () async {
      final fw = _FakeIpTables();

      expect(
          await fw.blockTCPPort(2223,
              allowedPorts: {2224}, allowAllPorts: false),
          isFalse);

      expect(
          await fw.acceptAddressOnTCPPort('1.2.3.4', 2223,
              allowedPorts: {2224}, allowAllPorts: false),
          isFalse);

      expect(await fw.listBlockedTCPPorts(allowedPorts: null), equals(<int>{}));
    });
  });
}
