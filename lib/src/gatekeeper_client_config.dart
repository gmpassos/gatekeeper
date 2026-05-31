import 'dart:convert';
import 'dart:io';

/// Optional configuration loaded from the `.gatekeeper` directory at the
/// current user's home (resolved on all OSes supported by Dart).
///
/// The directory may contain:
/// - `config.json`: a JSON object with optional `host`, `port`, `access-key`
///   and `verbose` entries, used as defaults for the client.
/// - `access-key`: a plain text file with the access key, used when neither the
///   `--access-key` option nor `config.json` provides one.
class GatekeeperClientConfig {
  final String? host;

  final int? port;

  final String? accessKey;

  final bool verbose;

  const GatekeeperClientConfig({
    this.host,
    this.port,
    this.accessKey,
    this.verbose = false,
  });

  /// Resolves the current user's home directory on all OSes supported by Dart.
  static String? resolveUserHome() {
    final env = Platform.environment;
    if (Platform.isWindows) {
      final userProfile = env['USERPROFILE'];
      if (userProfile != null && userProfile.isNotEmpty) return userProfile;
      final homeDrive = env['HOMEDRIVE'];
      final homePath = env['HOMEPATH'];
      if (homeDrive != null &&
          homeDrive.isNotEmpty &&
          homePath != null &&
          homePath.isNotEmpty) {
        return '$homeDrive$homePath';
      }
      return null;
    }
    final home = env['HOME'];
    if (home != null && home.isNotEmpty) return home;
    return null;
  }

  /// The `.gatekeeper` directory at the user's home, or `null` if the home
  /// directory can't be resolved.
  static Directory? resolveDirectory() {
    final home = resolveUserHome();
    if (home == null || home.isEmpty) return null;
    return Directory('$home${Platform.pathSeparator}.gatekeeper');
  }

  /// Loads the configuration from the `.gatekeeper` directory.
  ///
  /// Returns an empty configuration if the directory or its files are absent.
  static GatekeeperClientConfig load() {
    final dir = resolveDirectory();
    if (dir == null || !dir.existsSync()) {
      return const GatekeeperClientConfig();
    }

    String? host;
    int? port;
    String? accessKey;
    var verbose = false;

    final configFile = File('${dir.path}${Platform.pathSeparator}config.json');
    if (configFile.existsSync()) {
      try {
        final content = configFile.readAsStringSync().trim();
        if (content.isNotEmpty) {
          final json = jsonDecode(content);
          if (json is Map) {
            host = _asString(json['host']);
            port = _asInt(json['port']);
            accessKey =
                _asString(json['access-key']) ?? _asString(json['accessKey']);
            verbose = json['verbose'] == true;
          }
        }
      } catch (e) {
        stderr.writeln(
            'Error reading Gatekeeper config file `${configFile.path}`: $e');
      }
    }

    // Optional dedicated access-key file, used only when `config.json` didn't
    // provide one:
    if (accessKey == null || accessKey.isEmpty) {
      final keyFile = File('${dir.path}${Platform.pathSeparator}access-key');
      if (keyFile.existsSync()) {
        try {
          final key = keyFile.readAsStringSync().trim();
          if (key.isNotEmpty) accessKey = key;
        } catch (e) {
          stderr.writeln(
              'Error reading Gatekeeper access-key file `${keyFile.path}`: $e');
        }
      }
    }

    return GatekeeperClientConfig(
      host: host,
      port: port,
      accessKey: accessKey,
      verbose: verbose,
    );
  }

  static String? _asString(Object? value) {
    if (value == null) return null;
    final s = value.toString().trim();
    return s.isEmpty ? null : s;
  }

  static int? _asInt(Object? value) {
    if (value == null) return null;
    if (value is int) return value;
    return int.tryParse(value.toString().trim());
  }
}
