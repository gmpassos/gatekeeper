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
