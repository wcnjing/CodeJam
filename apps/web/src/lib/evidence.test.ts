import { describe, expect, it } from "vitest";
import { loadAgentEvidence, type EvidenceLoadDeps } from "./evidence";
import type { NetworkDenial, PolicyDecision } from "../types";

/**
 * The panel these feed exists to show ONE agent's network evidence. So a
 * response that arrives after the operator has moved on is not a cosmetic
 * flicker: it is agent A's containment record rendered under agent B's name,
 * which is the exact confusion the evidence is there to prevent.
 *
 * The server scopes both endpoints to the requested agent already, so nothing
 * here is a disclosure boundary. It is the display being wrong about whose
 * evidence it is showing, in the surface an operator reads to decide whether to
 * trust the control.
 */

const denial = (agentId: string, host: string): NetworkDenial => ({
  id: "denial-" + agentId + "-" + host,
  agentId,
  runId: "run-" + agentId,
  host,
  port: 443,
  reason: "destination not allowlisted",
  source: "egress-broker",
  observedAt: "2026-09-01T00:00:00.000Z",
});

const decision = (agentId: string): PolicyDecision => ({
  id: "policy-" + agentId,
  agentId,
  runId: "run-" + agentId,
  rule: "network-egress-denied",
  command: "curl https://example.invalid",
  detail: "Command contacts non-allowlisted host(s).",
  enforced: true,
  decidedAt: "2026-09-01T00:00:00.000Z",
});

/** A promise whose resolution the test controls, so ordering is not a race. */
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

interface Harness {
  deps: EvidenceLoadDeps;
  networkEvents: NetworkDenial[][];
  policyEvents: PolicyDecision[][];
}

function harness(
  selected: { id: string | null },
  overrides: Partial<EvidenceLoadDeps> = {},
): Harness {
  const networkEvents: NetworkDenial[][] = [];
  const policyEvents: PolicyDecision[][] = [];
  return {
    networkEvents,
    policyEvents,
    deps: {
      fetchNetworkEvents: async (agentId) => ({ networkEvents: [denial(agentId, "a.example")] }),
      fetchPolicyEvents: async (agentId) => ({ policyEvents: [decision(agentId)] }),
      // Exactly the condition every other refresh callback in App.tsx uses,
      // read at APPLY time rather than at request time.
      isCurrent: (agentId) => selected.id === agentId,
      setNetworkEvents: (events) => networkEvents.push(events),
      setPolicyEvents: (events) => policyEvents.push(events),
      ...overrides,
    },
  };
}

describe("per-agent evidence loading", () => {
  it("applies both kinds of evidence while the agent is still selected", async () => {
    const selected = { id: "agent-a" };
    const h = harness(selected);
    await loadAgentEvidence("agent-a", h.deps);

    expect(h.networkEvents).toHaveLength(1);
    expect(h.networkEvents[0]?.[0]?.agentId).toBe("agent-a");
    expect(h.policyEvents).toHaveLength(1);
    expect(h.policyEvents[0]?.[0]?.agentId).toBe("agent-a");
  });

  it("drops an in-flight NETWORK response that lands after the selection moved", async () => {
    // The regression. This fetch used to set state unconditionally while the
    // policy fetch beside it checked, so agent A's denials replaced agent B's.
    const selected = { id: "agent-a" };
    const gate = deferred<{ networkEvents: NetworkDenial[] }>();
    const h = harness(selected, {
      fetchNetworkEvents: () => gate.promise,
    });

    const inFlight = loadAgentEvidence("agent-a", h.deps);
    // The operator switches agents while A's request is still open.
    selected.id = "agent-b";
    gate.resolve({ networkEvents: [denial("agent-a", "registry.npmjs.org")] });
    await inFlight;

    expect(h.networkEvents, "agent A's denials were applied under agent B").toEqual([]);
    // The policy fetch resolves after the switch too, and is dropped for the
    // same reason — that half was already correct and must stay correct.
    expect(h.policyEvents).toEqual([]);
  });

  it("shows only B's evidence when A's late response races B's", async () => {
    // The end state a reviewer actually sees: two loads in flight, the stale
    // one resolving last, and the timeline still showing the selected agent.
    const selected = { id: "agent-a" };
    const slowA = deferred<{ networkEvents: NetworkDenial[] }>();
    const applied: NetworkDenial[][] = [];
    const deps: EvidenceLoadDeps = {
      fetchNetworkEvents: (agentId) =>
        agentId === "agent-a"
          ? slowA.promise
          : Promise.resolve({ networkEvents: [denial(agentId, "b.example")] }),
      fetchPolicyEvents: async (agentId) => ({ policyEvents: [decision(agentId)] }),
      isCurrent: (agentId) => selected.id === agentId,
      setNetworkEvents: (events) => applied.push(events),
      setPolicyEvents: () => undefined,
    };

    const loadA = loadAgentEvidence("agent-a", deps);
    selected.id = "agent-b";
    await loadAgentEvidence("agent-b", deps);
    // A's response arrives last, which is the ordering that used to win.
    slowA.resolve({ networkEvents: [denial("agent-a", "registry.npmjs.org")] });
    await loadA;

    expect(applied).toHaveLength(1);
    expect(applied[0]?.every((event) => event.agentId === "agent-b")).toBe(true);
  });

  it("leaves the previous list alone when the network fetch fails", async () => {
    // "Could not read" must never render as "nothing was refused". The loader
    // sets nothing rather than clearing, and the run's own networkEvidence
    // field is what says which of the two it was.
    const selected = { id: "agent-a" };
    const h = harness(selected, {
      fetchNetworkEvents: () => Promise.reject(new Error("network down")),
    });

    await loadAgentEvidence("agent-a", h.deps);

    expect(h.networkEvents).toEqual([]);
    // A failed network fetch must not stop policy evidence loading.
    expect(h.policyEvents).toHaveLength(1);
  });

  it("drops everything once the component is unmounted", async () => {
    // `isCurrent` folds in mountedRef, so an unmounted component applies
    // nothing at all rather than setting state on a dead tree.
    const h = harness({ id: "agent-a" }, { isCurrent: () => false });
    await loadAgentEvidence("agent-a", h.deps);

    expect(h.networkEvents).toEqual([]);
    expect(h.policyEvents).toEqual([]);
  });
});
