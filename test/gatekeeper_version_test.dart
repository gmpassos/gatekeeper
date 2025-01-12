@TestOn('vm')
@Tags(['version'])
library;

import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:pubspec_parse/pubspec_parse.dart';
import 'package:test/test.dart';

void main() {
  group('Gatekeeper.version', () {
    setUp(() {});

    test('Check Version', () async {
      var projectDirectory = Directory.current;

      print(projectDirectory);

      var pubspecFile = File(path.join(projectDirectory.path, 'pubspec.yaml'));

      print('pubspecFile: $pubspecFile');

      var pubspecContent = await pubspecFile.readAsString();

      var pubSpec = Pubspec.parse(pubspecContent);

      print('PubSpec.name: ${pubSpec.name}');
      print('PubSpec.version: ${pubSpec.version}');

      var apiRootFile = File(
          path.join(projectDirectory.path, 'lib/src/gatekeeper_const.dart'));

      var apiRootSource = apiRootFile.readAsStringSync();

      var regExpVersion = RegExp(r"const\s+gatekeeperVersion\s+=\s+'(.*?)'");

      var gatekeeperVersion =
          regExpVersion.firstMatch(apiRootSource)?.group(1) ??
              (throw StateError("Can't parse `Gatekeeper` version."));

      print('Gatekeeper: $gatekeeperVersion');

      expect(pubSpec.version.toString(), equals(gatekeeperVersion),
          reason:
              'Gatekeeper.version[$gatekeeperVersion] != PubSpec.version[${pubSpec.version}]');
    });
  });
}
