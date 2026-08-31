/**
 * Entrypoint for the egress broker sidecar.
 *
 * Runs inside its own container, dual-homed: attached to the Agent's isolated
 * network (where it is the only reachable thing) and to a network with an
 * outbound route (where it is the only thing that may leave). It allowlists
 * the endpoints named in EGRESS_ALLOW_URL — the model API plus the effective
 * command-policy allowlist, comma-separated — and refuses everything else. It
 * also answers DNS on EGRESS_DNS_PORT (default 53) for the Agent network,
 * relaying queries to its own resolvers, because an `--internal` network has
 * no outbound DNS at all.
 *
 * Deliberately dependency-free — only node builtins — so the sidecar image is a
 * bare node base plus one bundled file, and the thing standing between an
 * untrusted Agent and the internet has no supply chain of its own.
 */
import {
  createDnsForwarder,
  createEgressBroker,
  parseEgressEndpoints,
} from "./egress-broker.js";

const allowUrls = (process.env.EGRESS_ALLOW_URL ?? "").trim();
const port = Number(process.env.EGRESS_LISTEN_PORT ?? 8080);
const host = (process.env.EGRESS_LISTEN_HOST ?? "0.0.0.0").trim();
const dnsPort = Number(process.env.EGRESS_DNS_PORT ?? 53);

if (!allowUrls) {
  console.error("EGRESS_ALLOW_URL is required: the broker refuses to run without an allowlist.");
  process.exit(2);
}
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  console.error("EGRESS_LISTEN_PORT is not a valid port: " + process.env.EGRESS_LISTEN_PORT);
  process.exit(2);
}
if (!Number.isInteger(dnsPort) || dnsPort < 1 || dnsPort > 65535) {
  console.error("EGRESS_DNS_PORT is not a valid port: " + process.env.EGRESS_DNS_PORT);
  process.exit(2);
}

let allow;
try {
  allow = parseEgressEndpoints(allowUrls);
} catch (error) {
  console.error("EGRESS_ALLOW_URL is not usable: " + (error as Error).message);
  process.exit(2);
}
if (allow.length === 0) {
  console.error("EGRESS_ALLOW_URL must name at least one endpoint.");
  process.exit(2);
}

/**
 * Which run this broker belongs to.
 *
 * A denial is only evidence if it can be correlated, and the broker is a
 * detached container that otherwise knows nothing about the run it serves. The
 * orchestrator stamps these in at `buildBrokerRunArgs` time. Absent (a broker
 * started by hand, or by `verify:egress`) they are empty strings and the record
 * is still well-formed and still readable -- an uncorrelated denial is worth
 * more than no denial.
 */
const runId = (process.env.EGRESS_RUN_ID ?? "").trim();
const agentId = (process.env.EGRESS_AGENT_ID ?? "").trim();

/**
 * Splits `host:port` back apart on the LAST colon, the way the CONNECT parser
 * assembled it, so an IPv6 literal in brackets survives the round trip.
 * `target` is `-` for a request too malformed to name a destination.
 */
function splitTarget(target: string): { host: string; port: number } {
  const separator = target.lastIndexOf(":");
  if (separator < 1) return { host: target, port: 0 };
  const port = Number(target.slice(separator + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { host: target, port: 0 };
  }
  return { host: target.slice(0, separator), port };
}

const server = createEgressBroker({
  allow,
  // Denials are the interesting signal: each one is an Agent trying to reach
  // somewhere it may not. Logged to stderr so the run's container logs carry
  // them without being confused for broker output, and stamped with enough
  // context that the control plane can persist them as run evidence rather than
  // leaving containment invisible.
  onDenied: (reason, target) => {
    const { host, port } = splitTarget(target);
    console.error(
      JSON.stringify({
        event: "egress-denied",
        source: "egress-broker",
        runId,
        agentId,
        target,
        host,
        port,
        reason,
        at: new Date().toISOString(),
      }),
    );
  },
});

server.on("error", (error) => {
  console.error("Broker failed to listen: " + error.message);
  process.exit(1);
});

// The Agent's `--internal` network cannot resolve external names on its own;
// this is what makes allowlisted hosts reachable by name from the Agent.
const dns = createDnsForwarder({ port: dnsPort });
dns.udp.on("error", (error) => {
  console.error("DNS forwarder (UDP) failed: " + error.message);
  process.exit(1);
});
dns.tcp.on("error", (error) => {
  console.error("DNS forwarder (TCP) failed: " + error.message);
  process.exit(1);
});

server.listen(port, host, () => {
  console.log(
    JSON.stringify({
      event: "egress-broker-ready",
      listening: host + ":" + port,
      allow: allow.map((endpoint) => endpoint.host + ":" + endpoint.port).join(","),
      dns: dnsPort,
    }),
  );
});

// The Agent's run is what gives this process its lifetime; the orchestrator
// stops the container. Handle the signal so teardown is a clean exit rather
// than a kill after the grace period.
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, () => {
    dns.tcp.close();
    dns.udp.close();
    server.close(() => process.exit(0));
  });
}
