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

  // Accept connections on blocked port 8080:
  gatekeeper.acceptAddressOnTCPPort('192.168.0.100', 8080);

  // "Unaccept" connections on blocked port 8080:
  gatekeeper.unacceptAddressOnTCPPort('192.168.0.100', 8080);

  // "Unaccept" connections on all blocked ports:
  gatekeeper.unacceptAddressOnTCPPort('192.168.0.100', null);
}
