import 'dart:convert';

import 'package:gatekeeper/gatekeeper_client.dart';

/// Helper invoked as a subprocess (with a custom `HOME`/`USERPROFILE`) by
/// `gatekeeper_config_test.dart` to exercise [GatekeeperClientConfig.load],
/// which reads the `.gatekeeper` directory from the user's home.
///
/// Prints the loaded configuration as a single JSON line on stdout.
void main() {
  final c = GatekeeperClientConfig.load();
  print(jsonEncode({
    'host': c.host,
    'port': c.port,
    'accessKey': c.accessKey,
    'verbose': c.verbose,
  }));
}
