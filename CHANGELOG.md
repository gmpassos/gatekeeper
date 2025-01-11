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
