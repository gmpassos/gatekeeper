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
can list, block, and unblock ports — and allow-list specific source addresses (IPv4 **and** IPv6) — programmatically,
through inter-process communication (IPC), or remotely, providing a flexible and efficient solution for port management.

- **Dual-stack (IPv4 + IPv6):** rules are applied with `iptables` for IPv4 and `ip6tables` for IPv6.
- **Secure remote control:** the server/client protocol authenticates with an access key and uses an encrypted session.
- **Address allow-listing:** open a blocked port only to specific source addresses.

> **Note:** the `GatekeeperIpTables` driver runs `iptables`/`ip6tables`, so it requires **Linux** and **root**
> privileges (run the process as `root`, or via `sudo`). `ip6tables` is optional — when it is not installed, IPv6
> operations are skipped gracefully. For trying the API/CLI on other platforms, use the in-memory mock
> (`GatekeeperMock`, or `--mock` on the CLI).

## Usage

You can use `Gatekeeper` programmatically:

```dart
import 'package:gatekeeper/gatekeeper_iptables.dart';

void main() async {
  var gatekeeper = Gatekeeper(
    driver: GatekeeperIpTables(), // Use `iptables`/`ip6tables` to handle ports.
    allowedPorts: {2080, 2443}, // Only handle ports 2080 and 2443.
  );

  // List blocked TCP ports:
  var blockedTCPPorts = await gatekeeper.listBlockedTCPPorts();
  print("-- Blocked TCP ports: $blockedTCPPorts");

  // Block port 2080:
  var blocked = await gatekeeper.blockTCPPort(2080);
  print("-- Blocked 2080: $blocked");

  // Allow a specific source address on the blocked port (IPv4 or IPv6):
  await gatekeeper.acceptAddressOnTCPPort('192.168.0.10', 2080);
  await gatekeeper.acceptAddressOnTCPPort('2001:db8::1', 2080);

  // List accepted addresses:
  print("-- Accepted: ${await gatekeeper.listAcceptedAddressesOnTCPPorts()}");

  // Unblock port 2080:
  var unblocked = await gatekeeper.unblockTCPPort(2080);
  print("-- Unblocked 2080: $unblocked");

  // Try to block a not allowed port:
  var failedBlock = await gatekeeper.blockTCPPort(8080);
  print("-- Failed block of 8080: $failedBlock");
}
```

## CLI

Activate the `gatekeeper` commands:

```bash
dart pub global activate gatekeeper
```

### gatekeeper (server)

To run a `GatekeeperServer` listening on port `2243` and managing ports `2221,2222,2223`:

```bash
gatekeeper --port 2243 --access-key <ACCESS_KEY> --allowed-ports 2221,2222,2223
```

The access key is **required** and must be at least 32 characters long. If `--access-key` is omitted, the server prompts
for it (use `--access-key -` or `--access-key .` to read it from `stdin`). The server binds dual-stack by default, so it
accepts both IPv4 and IPv6 connections.

Options:

| Option | Description |
|---|---|
| `--port <port>` | **Required.** Port to listen on. |
| `--access-key <key>` | **Required.** Access key (length ≥ 32). `-` / `.` reads from `stdin`. |
| `--allowed-ports <p1,p2,...>` | Ports this server is allowed to manage. |
| `--allow-all-ports` | Allow managing any port (overrides `--allowed-ports`). |
| `--mock` | Use the in-memory mock driver instead of `iptables` (for testing). |
| `--verbose` | Verbose logging. |

> Because it manages `iptables`/`ip6tables`, the server must run on Linux as `root` (e.g. `sudo gatekeeper ...`),
> unless `--mock` is used.

### gatekeeper_client

To connect to a `GatekeeperServer` on host `server-host` port `2243`:

```bash
gatekeeper_client server-host 2243 --access-key <ACCESS_KEY>
```

Once connected, it opens an interactive prompt. Available commands (type `help` or `?` to list them):

| Command | Description |
|---|---|
| `list` \| `ls` \| `l` `[ports\|accepts\|all]` | List blocked ports and/or accepted addresses (default: `all`). |
| `block <port>` | Block a TCP port (applied to both IPv4 and IPv6). |
| `unblock <port>` | Unblock a TCP port (IPv4 and IPv6). |
| `accept <address\|.> <port>` | Allow a source address on a port. `.` means **this client** — whitelists **both** its IPv4 and IPv6 address. |
| `unaccept <address\|.> [port]` | Remove an accepted address (all ports if omitted). `.` means this client. |
| `myip` \| `my ip` | Show this client's IP as seen by the server. |
| `help` \| `?` | Show the list of commands. |
| `exit` | Disconnect and quit. |

For example, to open blocked port `22` to the machine you are connecting from (both IPv4 and IPv6):

```text
> accept . 22
-- Accepted IPv4 `203.0.113.5` on port 22: true
-- Accepted IPv6 `2001:db8::1` on port 22: true
-- Accepted IPs on port 22: 203.0.113.5, 2001:db8::1
```

> To resolve both families, the client briefly opens an auxiliary connection over the missing family, so the server must
> be reachable over both IPv4 and IPv6 for both to be whitelisted; otherwise only the reachable family is used.

#### Configuration (`.gatekeeper` directory)

The client also looks for a `.gatekeeper` directory in the current user's home
(resolved on all OSes supported by Dart) to load default options:

- `~/.gatekeeper/config.json`: a JSON object with optional defaults:

  ```json
  {
    "host": "localhost",
    "port": 2243,
    "access-key": "<ACCESS_KEY>",
    "verbose": false
  }
  ```

- `~/.gatekeeper/access-key`: a plain text file with the access key, used when
  neither the `--access-key` option nor `config.json` provides one.

Command-line arguments/options take precedence over the `.gatekeeper`
configuration. The access key may also be passed with `--access-key -` (or `.`)
to read it from `stdin`.

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: https://github.com/gmpassos/gatekeeper/issues

## Author

Graciliano M. Passos: [gmpassos@GitHub][github].

[github]: https://github.com/gmpassos

## License

Dart free & open-source [license](https://github.com/dart-lang/stagehand/blob/master/LICENSE).
