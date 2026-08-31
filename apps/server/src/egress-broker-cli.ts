/**
 * Entrypoint for the egress broker sidecar.
 *
 * Runs inside its own container, dual-homed: attached to the Agent's isolated
 * network (where it is the only reachable thing) and to a network with an
 * outbound route (where it is the only thing that may leave). It allowlists
 * the endpoints named in EGRESS_ALLOW_URL — the model API plus the effective
 * command-policy allowlist, comma-separated — and refuses everything else.
 *
 * Deliberately dependency-free — only node builtins — so the sidecar image is a
 * bare node base plus one bundled file, and the thing standing between an
 * untrusted Agent and the internet has no supply chain of its own.
 */
import { createEgressBroker, parseEgressEndpoints } from "./egress-broker.js";

const allowUrls = (process.env.EGRESS_ALLOW_URL ?? "").trim();
const port = Number(process.env.EGRESS_LISTEN_PORT ?? 8080);
const host = (process.env.EGRESS_LISTEN_HOST ?? "0.0.0.0").trim();

if (!allowUrls) {
  console.error("EGRESS_ALLOW_URL is required: the broker refuses to run without an allowlist.");
  process.exit(2);
}
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  console.error("EGRESS_LISTEN_PORT is not a valid port: " + process.env.EGRESS_LISTEN_PORT);
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

const server = createEgressBroker({
  allow,
  // Denials are the interesting signal: each one is an Agent trying to reach
  // somewhere it may not. Logged to stderr so the run's container logs carry
  // them without being confused for broker output.
  onDenied: (reason, target) => {
    console.error(JSON.stringify({ event: "egress-denied", target, reason }));
  },
});

server.on("error", (error) => {
  console.error("Broker failed to listen: " + error.message);
  process.exit(1);
});

server.listen(port, host, () => {
  console.log(
    JSON.stringify({
      event: "egress-broker-ready",
      listening: host + ":" + port,
      allow: allow.map((endpoint) => endpoint.host + ":" + endpoint.port).join(","),
    }),
  );
});

// The Agent's run is what gives this process its lifetime; the orchestrator
// stops the container. Handle the signal so teardown is a clean exit rather
// than a kill after the grace period.
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
