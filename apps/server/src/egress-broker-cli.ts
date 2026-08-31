/**
 * Entrypoint for the egress broker sidecar.
 *
 * Runs inside its own container, dual-homed: attached to the Agent's isolated
 * network (where it is the only reachable thing) and to a network with an
 * outbound route (where it is the only thing that may leave).
 *
 * Its allowlist comes from two deliberately separate variables:
 *
 *   EGRESS_ALLOW_URL       the model endpoint, always present, platform-owned.
 *   EGRESS_APPROVED_URLS   comma-separated, added by a human approval, scoped
 *                          to this one continuation run.
 *
 * They stay separate rather than being concatenated by the caller so that the
 * container's env and the readiness log say which entries a person put there.
 * An operator reading `docker inspect` on a live broker can tell the standing
 * allowance from the granted one without consulting anything else.
 *
 * Deliberately dependency-free — only node builtins — so the sidecar image is a
 * bare node base plus one bundled file, and the thing standing between an
 * untrusted Agent and the internet has no supply chain of its own.
 */
import { brokerAllowlist, createEgressBroker, type EgressEndpoint } from "./egress-broker.js";

const port = Number(process.env.EGRESS_LISTEN_PORT ?? 8080);
const host = (process.env.EGRESS_LISTEN_HOST ?? "0.0.0.0").trim();

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  console.error("EGRESS_LISTEN_PORT is not a valid port: " + process.env.EGRESS_LISTEN_PORT);
  process.exit(2);
}

/**
 * A missing model endpoint, or an approved entry we cannot parse, is a refusal
 * to start rather than a silent drop — see brokerAllowlist. Exiting non-zero
 * means the broker never binds, so the run's readiness gate fails it closed.
 */
let allowlist: EgressEndpoint[];
try {
  allowlist = brokerAllowlist(process.env.EGRESS_ALLOW_URL ?? "", process.env.EGRESS_APPROVED_URLS ?? "");
} catch (error) {
  console.error((error as Error).message);
  process.exit(2);
}

const [allow, ...approved] = allowlist as [EgressEndpoint, ...EgressEndpoint[]];

const server = createEgressBroker({
  allow: allowlist,
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

const label = (endpoint: EgressEndpoint) => endpoint.host + ":" + endpoint.port;

server.listen(port, host, () => {
  console.log(
    JSON.stringify({
      event: "egress-broker-ready",
      listening: host + ":" + port,
      // Reported under two keys, matching the two variables: the readiness line
      // is the record of what this run was permitted, and "which of these did a
      // human grant" is the question that record has to be able to answer.
      allow: label(allow),
      approved: approved.map(label),
    }),
  );
});

// The Agent's run is what gives this process its lifetime; the orchestrator
// stops the container. Handle the signal so teardown is a clean exit rather
// than a kill after the grace period.
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
