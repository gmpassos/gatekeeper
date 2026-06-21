import 'dart:convert';
import 'dart:io';

import 'package:gatekeeper/gatekeeper_client.dart';
import 'package:test/test.dart';

void main() {
  group('GatekeeperClientConfig (pure)', () {
    test('constructor defaults', () {
      const c = GatekeeperClientConfig();
      expect(c.host, isNull);
      expect(c.port, isNull);
      expect(c.accessKey, isNull);
      expect(c.verbose, isFalse);
    });

    test('resolveUserHome matches HOME on POSIX', () {
      if (Platform.isWindows) return;
      expect(GatekeeperClientConfig.resolveUserHome(),
          equals(Platform.environment['HOME']));
    });

    test('resolveDirectory points at the `.gatekeeper` dir', () {
      final dir = GatekeeperClientConfig.resolveDirectory();
      // Null only if the home dir can't be resolved (not the case in CI).
      if (dir != null) {
        expect(dir.path, endsWith('.gatekeeper'));
      }
    });

    test('load does not throw', () {
      expect(() => GatekeeperClientConfig.load(), returnsNormally);
    });
  });

  group('GatekeeperClientConfig.load (subprocess with custom HOME)', () {
    Future<Map<String, dynamic>> loadWithHome(Directory home) async {
      final env = Map<String, String>.from(Platform.environment);
      env['HOME'] = home.path;
      env['USERPROFILE'] = home.path; // Windows fallback.

      final result = await Process.run(
        Platform.resolvedExecutable,
        ['run', 'test/config_probe.dart'],
        environment: env,
      );

      expect(result.exitCode, equals(0),
          reason: 'stderr: ${result.stderr}\nstdout: ${result.stdout}');

      final lines = (result.stdout as String)
          .trim()
          .split('\n')
          .where((l) => l.startsWith('{'))
          .toList();
      return jsonDecode(lines.last) as Map<String, dynamic>;
    }

    test('empty home -> empty config', () async {
      final home = Directory.systemTemp.createTempSync('gk_empty');
      try {
        final cfg = await loadWithHome(home);
        expect(cfg['host'], isNull);
        expect(cfg['port'], isNull);
        expect(cfg['accessKey'], isNull);
        expect(cfg['verbose'], isFalse);
      } finally {
        home.deleteSync(recursive: true);
      }
    });

    test('config.json is parsed', () async {
      final home = Directory.systemTemp.createTempSync('gk_json');
      try {
        Directory('${home.path}/.gatekeeper').createSync();
        File('${home.path}/.gatekeeper/config.json').writeAsStringSync(
            '{"host":"example.com","port":2243,'
            '"access-key":"the-key","verbose":true}');

        final cfg = await loadWithHome(home);
        expect(cfg['host'], equals('example.com'));
        expect(cfg['port'], equals(2243));
        expect(cfg['accessKey'], equals('the-key'));
        expect(cfg['verbose'], isTrue);
      } finally {
        home.deleteSync(recursive: true);
      }
    });

    test('access-key file used when config.json omits it', () async {
      final home = Directory.systemTemp.createTempSync('gk_keyfile');
      try {
        Directory('${home.path}/.gatekeeper').createSync();
        File('${home.path}/.gatekeeper/config.json')
            .writeAsStringSync('{"host":"h","port":10}');
        File('${home.path}/.gatekeeper/access-key')
            .writeAsStringSync('  key-from-file  \n');

        final cfg = await loadWithHome(home);
        expect(cfg['host'], equals('h'));
        expect(cfg['port'], equals(10));
        expect(cfg['accessKey'], equals('key-from-file'));
      } finally {
        home.deleteSync(recursive: true);
      }
    });

    test('invalid config.json is tolerated', () async {
      final home = Directory.systemTemp.createTempSync('gk_bad');
      try {
        Directory('${home.path}/.gatekeeper').createSync();
        File('${home.path}/.gatekeeper/config.json')
            .writeAsStringSync('{ not valid json ');

        final cfg = await loadWithHome(home);
        // Falls back to an empty config rather than throwing.
        expect(cfg['host'], isNull);
        expect(cfg['port'], isNull);
      } finally {
        home.deleteSync(recursive: true);
      }
    });
  });
}
