import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import {
  EgressIsolation,
  approvedHostUrl,
  buildApprovedUrls,
  buildBrokerConnectArgs,
  buildBrokerRunArgs,
  buildNetworkCreateArgs,
  buildBrokerProbeArgs,
  type EngineResult,
} from "./network-isolation.js";

const config = loadConfig({
  NODE_ENV: "test",
  ARK_API_KEY: "k",
  ARK_MODEL: "ep-test",
  ARK_BASE_URL: "https://ark.example.invalid/api/v3",
  RUNTIME_PROVIDER: "container",
  RUNTIME_INSTANCE_ID: "test-instance",
  CONTAINER_EGRESS_ISOLATION: "true",
  CONTAINER_USER: "1000:1000",
});

const ok: EngineResult = { code: 0, stdout: "", stderr: "" };
const fail = (stderr: string): EngineResult => ({ code: 1, stdout: "", stderr });

/** Records every engine invocation so ordering can be asserted, not just calls. */
function recorder(responses: (args: string[]) => EngineResult = () => ok) {
  const calls: string[][] = [];
  return {
    calls,
    exec: async (args: string[]) => {
      calls.push(args);
      return responses(args);
    },
  };
}

/** A stable label per invocation: the command, plus the object it acts on. */
const verbs = (calls: string[][]) =>
  calls.map((c) => {
    if (c[0] === "network") return "network " + c[1];
    if (c[0] === "stop") return "stop " + c[c.length - 1];
    return c[0]!;
  });

describe("isolation argv", () => {
  it("creates the network with --internal, which is the whole control", () => {
    // Without --internal the engine installs a NAT gateway and the Agent has a
    // route out regardless of what the proxy variables say.
    expect(buildNetworkCreateArgs("net-1")).toContain("--internal");
  });

  it("starts the broker contained as tightly as the Agent", () => {
    const args = buildBrokerRunArgs({
      broker: "b", network: "n", image: "img", allowUrl: "https://ark.example.invalid", port: 8080, user: "1000:1000",
    });
    expect(args).toContain("--read-only");
    expect(args).toContain("no-new-privileges");
    expect(args).toContain("ALL"); // --cap-drop ALL
    expect(args).toContain("EGRESS_ALLOW_URL=https://ark.example.invalid");
    expect(args[args.indexOf("--network") + 1]).toBe("n");
  });

  it("gives the broker a second, outbound network", () => {
    expect(buildBrokerConnectArgs("b", "bridge")).toEqual(["network", "connect", "bridge", "b"]);
  });

  it("passes an approved host in its own variable, not folded into the Ark one", () => {
    // Separate variables are the point: an operator reading `inspect` on a live
    // broker has to be able to tell the standing allowance from the one a human
    // granted for this run.
    const args = buildBrokerRunArgs({
      broker: "b", network: "n", image: "img", allowUrl: "https://ark.example.invalid",
      approvedUrls: ["https://registry.npmjs.org"], port: 8080, user: "1000:1000",
    });
    expect(args).toContain("EGRESS_ALLOW_URL=https://ark.example.invalid");
    expect(args).toContain("EGRESS_APPROVED_URLS=https://registry.npmjs.org");
  });

  it("omits the approval variable entirely when nothing was granted", () => {
    // Absent, not empty: an ordinary run's broker should carry no approval
    // state at all, so "was anything granted here?" is answerable by looking.
    const args = buildBrokerRunArgs({
      broker: "b", network: "n", image: "img", allowUrl: "https://ark.example.invalid",
      port: 8080, user: "1000:1000",
    });
    expect(args.some((arg) => arg.startsWith("EGRESS_APPROVED_URLS"))).toBe(false);
  });
});

describe("approved hosts become endpoints", () => {
  it("defaults a bare host to 443", () => {
    // What the policy engine extracts is a hostname, not a URL. The entry that
    // produced it was an HTTPS destination, so 443 is the honest default.
    expect(approvedHostUrl("registry.npmjs.org")).toBe("https://registry.npmjs.org");
  });

  it("keeps a port the entry names for itself", () => {
    // An approval for :8443 must not silently widen into an approval for 443.
    expect(approvedHostUrl("example.com:8443")).toBe("https://example.com:8443");
  });

  it("brackets a bare IPv6 literal", () => {
    // The policy layer strips the brackets; a URL needs them back, or
    // 2001:db8::1 parses as host "2001" on port "db8".
    expect(approvedHostUrl("2001:db8::1")).toBe("https://[2001:db8::1]");
  });

  it("refuses an entry it cannot turn into an endpoint", () => {
    // Fail closed and loudly. Dropping it would leave an approval recorded as
    // honoured and an Agent that still cannot reach the host.
    expect(() => approvedHostUrl("not a host")).toThrow();
    expect(() => approvedHostUrl("")).toThrow();
  });

  it("refuses a comma, which is the delimiter and not a forbidden host character", () => {
    // `new URL("https://a,b")` parses with hostname "a,b", so without this one
    // grant would arrive at the broker as two allowlist entries.
    expect(() => approvedHostUrl("registry.npmjs.org,attacker.example")).toThrow(/comma/);
  });

  it("deduplicates so the broker env is stable", () => {
    expect(buildApprovedUrls(["example.com", "example.com"])).toEqual(["https://example.com"]);
  });
});

describe("EgressIsolation lifecycle", () => {
  it("clears a stale topology, then creates, starts and dual-homes in order", async () => {
    const { calls, exec } = recorder();
    const handle = await new EgressIsolation(config, exec).setup("agent-1");

    expect(handle).toEqual({
      network: "sentinel-test-instance-agent-1-net",
      broker: "sentinel-test-instance-agent-1-broker",
    });
    // Stale cleanup first: names are deterministic, so a crashed previous run
    // would otherwise make "already exists" the normal startup path.
    expect(verbs(calls)).toEqual([
      "stop sentinel-test-instance-agent-1-broker",
      "network rm",
      "network create",
      "run",
      "network connect",
    ]);
  });

  it("refuses to create anything for a grant it cannot express", async () => {
    // Before the network exists, so a malformed grant is a readable error on
    // the host rather than a sidecar that exits 2 during the readiness wait
    // and reads as an infrastructure flake.
    const { calls, exec } = recorder();
    await expect(
      new EgressIsolation(config, exec).setup("agent-1", ["not a host"]),
    ).rejects.toThrow();
    expect(calls).toHaveLength(0);
  });

  it("carries the run's approved hosts into the broker it starts", async () => {
    const { calls, exec } = recorder();
    await new EgressIsolation(config, exec).setup("agent-1", ["registry.npmjs.org"]);
    const run = calls.find((c) => c[0] === "run")!;
    expect(run).toContain("EGRESS_APPROVED_URLS=https://registry.npmjs.org");
  });

  it("removes the network when the broker will not start", async () => {
    const { calls, exec } = recorder((args) =>
      args[0] === "run" ? fail("no such image") : ok,
    );
    await expect(new EgressIsolation(config, exec).setup("agent-1")).rejects.toThrow(
      /Could not start the egress broker: no such image/,
    );
    // The network must not survive the failure, or the next run inherits it.
    expect(verbs(calls).slice(-1)).toEqual(["network rm"]);
  });

  it("tears down both when the broker cannot be given an outbound network", async () => {
    const { calls, exec } = recorder((args) =>
      args[0] === "network" && args[1] === "connect" ? fail("bridge missing") : ok,
    );
    await expect(new EgressIsolation(config, exec).setup("agent-1")).rejects.toThrow(
      /outbound network: bridge missing/,
    );
    expect(verbs(calls).slice(-2)).toEqual(["stop sentinel-test-instance-agent-1-broker", "network rm"]);
  });

  it("fails loudly when the network cannot be created", async () => {
    const { exec } = recorder((args) =>
      args[0] === "network" && args[1] === "create" ? fail("pool exhausted") : ok,
    );
    await expect(new EgressIsolation(config, exec).setup("agent-1")).rejects.toThrow(
      /isolated network: pool exhausted/,
    );
  });

  it("tears down the broker before the network it is attached to", async () => {
    const { calls, exec } = recorder();
    await new EgressIsolation(config, exec).teardown({ network: "n", broker: "b" });
    expect(verbs(calls)).toEqual(["stop b", "network rm"]);
  });
});

describe("broker readiness", () => {
  it("probes through the engine, from inside the broker", async () => {
    // The previous check connected from the host to the broker's container
    // name. Nothing on the host can resolve that name, and the broker publishes
    // no host port, so the probe could never succeed and every isolated run
    // failed at the gate. Readiness is only observable through the engine.
    const args = buildBrokerProbeArgs("b", 8080);
    expect(args.slice(0, 3)).toEqual(["exec", "b", "node"]);
    expect(args.at(-1)).toContain("port:8080");
    // By name, not by loopback. A loopback probe is green while the Agent
    // cannot resolve the broker at all, which is the failure this catches.
    expect(args.at(-1)).toContain('host:"b"');
    expect(args.at(-1)).not.toContain("127.0.0.1");
  });

  it("returns true as soon as the probe succeeds", async () => {
    const { calls, exec } = recorder();
    const ready = await new EgressIsolation(config, exec).waitUntilReady(
      { network: "n", broker: "b" },
      3_000,
      50,
    );
    expect(ready).toBe(true);
    expect(calls.filter((c) => c[0] === "exec")).toHaveLength(1);
  });

  it("keeps polling while the broker is still binding", async () => {
    let attempts = 0;
    const { exec } = recorder(() => (++attempts < 3 ? fail("not running") : ok));
    const ready = await new EgressIsolation(config, exec).waitUntilReady(
      { network: "n", broker: "b" },
      3_000,
      20,
    );
    expect(ready).toBe(true);
    expect(attempts).toBe(3);
  });

  it("returns false rather than hanging when the broker never answers", async () => {
    // The readiness check is what stops a broken sidecar from presenting as a
    // model outage, so its timeout has to be real.
    const { exec } = recorder(() => fail("no such container"));
    const ready = await new EgressIsolation(config, exec).waitUntilReady(
      { network: "n", broker: "b" },
      300,
      50,
    );
    expect(ready).toBe(false);
  });
});
