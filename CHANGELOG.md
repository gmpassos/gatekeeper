## 1.1.0

- IPv6 support (dual-stack):
  - `GatekeeperServer`: now binds `InternetAddress.anyIPv6` with `v6Only: false`
    by default, accepting both IPv4 and IPv6 connections. IPv4-mapped IPv6
    remote addresses (`::ffff:1.2.3.4`) are normalized to plain IPv4.
  - `GatekeeperIpTables`: manages IPv6 rules via `ip6tables` (optional; skipped
    gracefully when not installed):
    - `accept`/`unaccept` select `iptables` or `ip6tables` from the address
      family.
    - `block`/`unblock` apply to both `iptables` and `ip6tables`.
    - Listings merge results from both families.
- `gatekeeper_client`:
  - `accept . <port>` now whitelists **both** the client's IPv4 and IPv6
    addresses (the missing family is discovered via an auxiliary connection),
    and prints the concrete IP(s) accepted. `unaccept .` removes both.
  - Added `help` / `?` command listing all commands and their usage.
  - `connect` accepts an optional `addressType` to force the IP family;
    added `myIPs()` returning both families' addresses.
- `utils`: added `normalizeIpAddress` and `isIPv6Address` helpers.

## 1.0.12

- `bin/gatekeeper_client.dart`:
  - Load optional configuration from a `.gatekeeper` directory at the user's
    home (resolved on all OSes supported by Dart):
    - `config.json`: optional defaults for `host`, `port`, `access-key` and
      `verbose`.
    - `access-key`: optional plain text file with the access key.
  - Resolution order: command-line arguments/options take precedence over the
    `.gatekeeper` configuration, with an interactive prompt as the last resort
    for the access key.

## 1.0.11

- `GatekeeperIpTables`:
  - Extracted port validation into `_checkValidPort` (ports 10–65535).
  - Added `_checkAddress` and `_normalizeAddress` to validate and sanitize IP addresses.
  - Replaced repeated inline checks with these helpers for cleaner, safer code.

## 1.0.10

- `GatekeeperDriver`:
  - Added `isAcceptedAddress`.

- `GatekeeperIpTables`:
  - `unacceptAddressOnTCPPort`: checks if the address is "unaccepted" for return value.

- `bin/gatekeeper.dart`:
  - Parameter `access-key`: allow value `-` or `.` to read from `stdin`.

## 1.0.9

- `GatekeeperClient`:
  - `processCommand`: process command `myip`.

## 1.0.8

- `GatekeeperIpTables`:
  - `unacceptAddressOnTCPPort`: handle `iptables` output for IPv6.

- `GatekeeperClient`:
  - Added `myIP`.

- `GatekeeperServer`:
  - Process command `myip`.

## 1.0.7

- `GatekeeperDriver`:
  - `listAcceptedAddressesOnTCPPorts`: handle `iptables` output for IPv6.

- `bin/gatekeeper.dart`, `bin/gatekeeper_client.dart`:
  - Show version (`$gatekeeperVersion`).

## 1.0.6

- `SocketHandler`:
  - Fix `isClosed`.

## 1.0.5

- `SocketHandler`:
  - Added `isClosed`.
  - `_checkLogged`: check `isClosed`.

## 1.0.4

- `Gatekeeper`.
  - Added `VERSION`.

- `gatekeeper_server`:
  - `login`: also respond with the server version.
  - Added `_onSocketError`: block sockets with errors.
  - Added `_checkLogged`: close not logged sockets after 30s.
  - Added `_onInvalidSocketProtocol`: count errors for invalid protocol.

- pubspec_parse: ^1.5.0
- path: ^1.9.1

## 1.0.3

- New `AESEncryptor` and `ChainAESEncryptor`.

- `GatekeeperServer`, `GatekeeperClient`:
  - `login`: use `hashAccessKey`.
  - Added option `secure`.
    - Added secure layer.
    - Added `_exchangeSessionKey`.

- `GatekeeperIpTables`:
  - `unacceptAddressOnTCPPort`: fix for all ports.

- collection: ^1.19.1
- crypto: ^3.0.6
- encrypt: ^5.0.3
- pointycastle: ^3.9.1

- dependency_validator: ^5.0.2

## 1.0.2

- `Gatekeeper`, `GatekeeperDriver`, `GatekeeperClient`, `GatekeeperMock`, `GatekeeperIpTables`:
  - Added `listAcceptedAddressesOnTCPPorts`, `acceptAddressOnTCPPort`, `unacceptAddressOnTCPPort`, `isAcceptedAddressOnPort`.

- `GatekeeperMock`, `GatekeeperIpTables`:
  - Added option `verbose`.

- `GatekeeperClient`:
  - `processCommand`:
    - Added `list accepted`.
    - Added `list all`.
    - Added `accept` and `unaccept`

- `gatekeeper_server`:
  - Improve console logging.
  - Process:
    - `list accepted`.
    - `list all`.
    - `accept` and `unaccept`

## 1.0.1

- `GatekeeperServer`:
  - Added `_zoneGuarded` and `_onUncaughtError`.
  - Process command `disconnect`.

- `GatekeeperClient`:
  - Added `disconnect`.

- `gatekeeper`: added flag `-mock`
- `gatekeeper_client`: fix call to `client.processCommand`.

## 1.0.0

- Initial version.
