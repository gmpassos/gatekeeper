/// The [Gatekeeper] class manages TCP port access by interfacing with the
/// [GatekeeperDriver]. It provides functionality to list, block, and unblock
/// TCP ports with optional permission checks and sudo privileges.
///
/// This class allows the management of specific allowed ports and includes
/// a setting to allow or block all ports.
///
/// Example usage:
/// ```dart
/// var gatekeeper = Gatekeeper(driver: gatekeeperDriver);
/// await gatekeeper.listBlockedTCPPorts();
/// await gatekeeper.blockTCPPort(8080);
/// ```
class Gatekeeper {
  // ignore: non_constant_identifier_names
  static final VERSION = '1.0.4';

  /// The driver used to interact with the underlying system.
  final GatekeeperDriver driver;

  /// A flag that indicates whether the action requires sudo privileges.
  final bool sudo;

  /// A set of allowed ports. If [allowAllPorts] is true, this is ignored.
  final Set<int>? allowedPorts;

  /// A flag that allows or denies access to all ports. If true, all ports
  /// are allowed, overriding `allowedPorts`.
  final bool allowAllPorts;

  /// Creates a [Gatekeeper] instance with the given driver and options.
  ///
  /// - [driver]: The [GatekeeperDriver] to interact with the system.
  /// - [sudo]: Optional flag to enable sudo privileges. Defaults to `false`.
  /// - [allowedPorts]: Optional set of allowed ports. Defaults to `null`.
  /// - [allowAllPorts]: Optional flag to allow all ports. Defaults to `false`.
  Gatekeeper(
      {required this.driver,
      this.sudo = false,
      Set<int>? allowedPorts,
      this.allowAllPorts = false})
      : allowedPorts =
            allowedPorts != null ? Set.unmodifiable(allowedPorts) : null;

  /// Lists all the currently blocked TCP ports.
  ///
  /// Returns a [Future] that completes with a [Set] of blocked TCP ports.
  /// The ports are filtered based on the current settings for sudo and allowed
  /// ports.
  Future<Set<int>> listBlockedTCPPorts() {
    return driver.listBlockedTCPPorts(
        sudo: sudo, allowedPorts: allowAllPorts ? null : (allowedPorts ?? {}));
  }

  /// Blocks a specific TCP port.
  ///
  /// - [port]: The TCP port to be blocked.
  ///
  /// Returns a [Future] that completes with `true` if the operation succeeded,
  /// or `false` if it failed.
  Future<bool> blockTCPPort(int port) {
    return driver.blockTCPPort(port,
        allowedPorts: allowedPorts, allowAllPorts: allowAllPorts);
  }

  /// Unblocks a specific TCP port.
  ///
  /// - [port]: The TCP port to be unblocked.
  ///
  /// Returns a [Future] that completes with `true` if the operation succeeded,
  /// or `false` if it failed.
  Future<bool> unblockTCPPort(int port) {
    return driver.unblockTCPPort(port,
        allowedPorts: allowedPorts, allowAllPorts: allowAllPorts);
  }

  /// Lists all the currently accepted addresses on TCP ports.
  ///
  /// Returns a [Future] that completes with a [Set] of `({String address, in port})` entries.
  Future<Set<({String address, int port})>>
      listAcceptedAddressesOnTCPPorts() async {
    var set = await driver.listAcceptedAddressesOnTCPPorts(
        sudo: sudo, allowedPorts: allowedPorts);
    var set2 = set.map((e) => (address: e.$1, port: e.$2)).toSet();
    return set2;
  }

  /// Add rule to accept connections on a specified TCP [port] from the given [address].
  ///
  /// - [address]: The address (IP or hostname) to accept connections from.
  /// - [port]: The TCP port number to accept connections on.
  ///
  /// Returns a [Future] that completes with `true` if the operation succeeded,
  /// or `false` if it failed.
  Future<bool> acceptAddressOnTCPPort(String address, int port) async {
    return driver.acceptAddressOnTCPPort(address, port,
        allowedPorts: allowedPorts, allowAllPorts: allowAllPorts);
  }

  /// Reverses the acceptance ("unaccept") of an [address] on a specified TCP [port].
  ///
  /// - [address]: The IP address or hostname to unaccept.
  /// - [port]: The TCP port from which the address will be unaccepted. If `null` will remove from all ports.
  ///
  /// Returns:
  /// - A `Future<bool>` indicating whether the operation was successful.
  Future<bool> unacceptAddressOnTCPPort(String address, int? port) async {
    return driver.unacceptAddressOnTCPPort(address, port,
        allowedPorts: allowedPorts, allowAllPorts: allowAllPorts);
  }

  /// Resolves the [Gatekeeper] [driver].
  ///
  /// Returns a [Future] that completes with a [bool] indicating success or failure.
  Future<bool> resolve() => driver.resolve();

  @override
  String toString() {
    return 'Gatekeeper{driver: $driver, sudo: $sudo, allowedPorts: $allowedPorts, allowAllPorts: $allowAllPorts}';
  }
}

/// The [GatekeeperDriver] class is an abstract class that defines the contract
/// for interacting with the system to manage TCP port access, resolve binary
/// paths, and run commands.
///
/// This class provides the necessary methods to manage blocked TCP ports,
/// check whether a port is blocked, and resolve binary paths for commands.
/// It must be extended and implemented to provide the specific system behavior.
abstract class GatekeeperDriver {
  final Map<String, String> _resolveBinaryPathCache = {};

  /// Clears the cached binary path entries.
  void clearResolveBinaryPathCache() => _resolveBinaryPathCache.clear();

  /// Resolves the binary path for a given command, using a cached path if available.
  ///
  /// - [binaryCommand]: The command to resolve the binary path for.
  ///
  /// Returns a [Future] that completes with the resolved binary path as a [String].
  Future<String> resolveBinaryPathCached(String binaryCommand) async {
    return _resolveBinaryPathCache[binaryCommand] ??=
        await resolveBinaryPath(binaryCommand);
  }

  /// Resolves the binary path for a given command. See [resolveBinaryPathCached].
  ///
  /// - `binaryCommand`: The command to resolve the binary path for.
  ///
  /// Returns a [Future] that completes with the resolved binary path as a [String].
  Future<String> resolveBinaryPath(String binaryCommand);

  /// Runs a command using the specified binary path and arguments.
  ///
  /// - [binaryPath]: The path to the binary to execute.
  /// - [args]: A list of arguments to pass to the command.
  /// - [sudo]: Whether the command should be run with sudo privileges. Defaults to `false`.
  /// - [expectedExitCode]: The expected exit code from the command. If not provided accepts any exit code.
  ///
  /// Returns a [Future] that completes with the command's output as a [String].
  Future<String?> runCommand(String binaryPath, List<String> args,
      {bool sudo = false, int? expectedExitCode});

  /// Lists all the currently blocked TCP ports.
  ///
  /// - [sudo]: A flag indicating if sudo privileges should be used. Defaults to `false`.
  /// - [allowedPorts]: A set of allowed ports, or `null` to allow all ports.
  ///
  /// Returns a [Future] that completes with a [Set] of blocked TCP ports.
  Future<Set<int>> listBlockedTCPPorts(
      {bool sudo = false, Set<int>? allowedPorts});

  /// Blocks a specific TCP port.
  ///
  /// - [port]: The TCP port to be blocked.
  /// - [sudo]: A flag indicating if sudo privileges should be used. Defaults to `false`.
  /// - [allowedPorts]: A set of allowed ports. Ignored if [allowAllPorts] is true.
  /// - [allowAllPorts]: A flag indicating if all ports should be allowed.
  ///
  /// Returns a [Future] that completes with `true` if the port was successfully blocked, or `false` if it failed.
  Future<bool> blockTCPPort(int port,
      {bool sudo = false,
      required Set<int>? allowedPorts,
      required bool allowAllPorts});

  /// Unblocks a specific TCP port.
  ///
  /// - [port]: The TCP port to be unblocked.
  /// - [sudo]: A flag indicating if sudo privileges should be used. Defaults to `false`.
  /// - [allowedPorts]: A set of allowed ports. Ignored if [allowAllPorts] is true.
  /// - [allowAllPorts]: A flag indicating if all ports should be allowed.
  ///
  /// Returns a [Future] that completes with `true` if the port was successfully unblocked, or `false` if it failed.
  Future<bool> unblockTCPPort(int port,
      {bool sudo = false,
      required Set<int>? allowedPorts,
      required bool allowAllPorts});

  /// Checks whether a specific TCP port is blocked. See [listBlockedTCPPorts].
  ///
  /// - [port]: The TCP port to check.
  /// - [sudo]: A flag indicating if sudo privileges should be used. Defaults to `false`.
  /// - [allowedPorts]: A set of allowed ports, or `null` to allow all ports.
  ///
  /// Returns a [Future] that completes with `true` if the port is blocked, or `false` if it is not.
  Future<bool> isBlockedTCPPort(int port,
      {bool sudo = false, Set<int>? allowedPorts}) async {
    var blockedPorts =
        await listBlockedTCPPorts(sudo: sudo, allowedPorts: allowedPorts);
    var blocked = blockedPorts.contains(port);
    return blocked;
  }

  /// Lists all the currently accepted addresses on TCP ports.
  ///
  /// - [sudo]: A flag indicating if sudo privileges should be used. Defaults to `false`.
  /// - [allowedPorts]: A set of allowed ports, or `null` to allow all ports.
  ///
  /// Returns a [Future] that completes with a [Set] of `(address,port)` entries.
  Future<Set<(String, int)>> listAcceptedAddressesOnTCPPorts(
      {bool sudo = false, Set<int>? allowedPorts});

  /// Checks whether a specific [address] is accepted on a TCP [port].
  /// See also: [listAcceptedAddressesOnTCPPorts].
  ///
  /// - [address]: The address to check.
  /// - [port]: The TCP port to check.
  /// - [sudo]: Whether sudo privileges should be used. Defaults to `false`.
  /// - [allowedPorts]: A set of allowed ports, or `null` to allow all ports.
  ///
  /// Returns a [Future] that completes with `true` if the port is accepted, or `false` if it is not.
  Future<bool> isAcceptedAddressOnPort(String address, int port,
      {bool sudo = false, Set<int>? allowedPorts}) async {
    var accepts = await listAcceptedAddressesOnTCPPorts(
        sudo: sudo, allowedPorts: allowedPorts);
    var accepted = accepts.contains((address, port));
    return accepted;
  }

  /// Add rule to accept connections on a specified TCP [port] from the given [address].
  ///
  /// - [address]: The address (IP or hostname) to accept connections from.
  /// - [port]: The TCP port number to accept connections on.
  /// - [sudo]: Whether elevated permissions are required to configure the port (default: `false`).
  /// - [allowedPorts]: A set of allowed ports for validation. If `null`, validation is skipped.
  /// - [allowAllPorts]: Whether to allow connections on all ports, overriding `allowedPorts`.
  ///
  /// Returns a [Future] that completes with `true` if the operation succeeded,
  /// or `false` if it failed.
  Future<bool> acceptAddressOnTCPPort(String address, int port,
      {bool sudo = false,
      required Set<int>? allowedPorts,
      required bool allowAllPorts});

  /// Reverses the acceptance ("unaccept") of an [address] on a specified TCP [port].
  ///
  /// This method is used to revoke a previously accepted address on a given
  /// TCP port. Optionally, it can be executed with elevated privileges using `sudo`.
  ///
  /// - [address]: The IP address or hostname to unaccept.
  /// - [port]: The TCP port from which the address will be unaccepted. If `null` will remove from all ports.
  /// - [sudo]: Indicates whether the operation should be executed with sudo
  ///   privileges. Defaults to `false`.
  /// - [allowedPorts]: A set of ports that are allowed for this operation. If `null`,
  ///   no port restrictions apply.
  /// - [allowAllPorts]: A flag to override `allowedPorts` and allow all ports to
  ///   be unaccepted.
  ///
  /// Returns:
  /// - A `Future<bool>` indicating whether the operation was successful.
  Future<bool> unacceptAddressOnTCPPort(String address, int? port,
      {bool sudo = false,
      required Set<int>? allowedPorts,
      required bool allowAllPorts});

  /// Resolves this [GatekeeperDriver] instance to ensure that it can be used in this system.
  ///
  /// Returns a [Future] that completes with a [bool] indicating success or failure.
  Future<bool> resolve();
}
