# gatekeeper

[![pub package](https://img.shields.io/pub/v/gatekeeper.svg?logo=dart&logoColor=00b9fc)](https://pub.dartlang.org/packages/gatekeeper)
[![Null Safety](https://img.shields.io/badge/null-safety-brightgreen)](https://dart.dev/null-safety)
[![Dart CI](https://github.com/gmpassos/gatekeeper/actions/workflows/dart.yml/badge.svg?branch=master)](https://github.com/gmpassos/gatekeeper/actions/workflows/dart.yml)
[![GitHub Tag](https://img.shields.io/github/v/tag/gmpassos/gatekeeper?logo=git&logoColor=white)](https://github.com/gmpassos/gatekeeper/releases)
[![New Commits](https://img.shields.io/github/commits-since/gmpassos/gatekeeper/latest?logo=git&logoColor=white)](https://github.com/gmpassos/gatekeeper/network)
[![Last Commits](https://img.shields.io/github/last-commit/gmpassos/gatekeeper?logo=git&logoColor=white)](https://github.com/gmpassos/gatekeeper/commits/master)
[![Pull Requests](https://img.shields.io/github/issues-pr/gmpassos/gatekeeper?logo=github&logoColor=white)](https://github.com/gmpassos/gatekeeper/pulls)
[![Code size](https://img.shields.io/github/languages/code-size/gmpassos/gatekeeper?logo=github&logoColor=white)](https://github.com/gmpassos/gatekeeper)
[![License](https://img.shields.io/github/license/gmpassos/gatekeeper?logo=open-source-initiative&logoColor=green)](https://github.com/gmpassos/gatekeeper/blob/master/LICENSE)

`gatekeeper` is a Dart package for managing TCP ports, offering a manager, server, and client for seamless control. You
can list, block, and unblock ports programmatically, through inter-process communication (IPC), or remotely, providing a
flexible and efficient solution for port management.

## Usage

You can use `Gatekeeper` programmatically:

```dart
import 'package:gatekeeper/gatekeeper_iptables.dart';

void main() async {
  var gatekeeper = Gatekeeper(
    driver: GatekeeperIpTables(), // Use `iptables` to handle ports.
    allowedPorts: {2080, 2443}, // Only handle ports 2080 and 2443.
  );

  // List blocked TCP ports:
  var blockedTCPPorts = await gatekeeper.listBlockedTCPPorts();
  print("-- Blocked TCP ports: $blockedTCPPorts");

  // Block port 2222:
  var blocked = await gatekeeper.blockTCPPort(2080);
  print("-- Blocked 2080: $blocked");

  // Unblock port 2222:
  var unblocked = await gatekeeper.unblockTCPPort(2080);
  print("-- Unblocked 2080: $unblocked");

  // Try to block a not allowed port:
  var failedBlock = await gatekeeper.blockTCPPort(8080);
  print("-- Failed block of 2080: $failedBlock");
}
```

## CLI

Activate the `gatekeeper` commands:

```bash
dart pub global activate gatekeeper
```

### gatekeeper

To run a `GatekeeperServer` listening on port `2243` and managing ports `2221,2222,2223`:

```bash
gatekeeper --port 2243 --allowed-ports 2221,2222,2223
```

### gatekeeper_client

To connect to a `GatekeeperServer` on port `2243`:

```bash
gatekeeper_client server-host 2243
```

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: https://github.com/gmpassos/gatekeeper/issues

## Author

Graciliano M. Passos: [gmpassos@GitHub][github].

[github]: https://github.com/gmpassos

## License

Dart free & open-source [license](https://github.com/dart-lang/stagehand/blob/master/LICENSE).
