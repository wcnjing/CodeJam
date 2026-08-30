import { describe, expect, it } from "vitest";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import type { AgentService } from "./agent-service.js";

/**
 * Contract test for the `GET /api/evaluation` payload.
 *
 * `apps/web/src/types.ts` hand-copies the `EvaluationSummary` interface. There is
 * no shared import and no build-time link, so renaming a field here compiles
 * clean on both sides and breaks the dashboard only at runtime, in front of
 * whoever is watching the demo.
 *
 * This is not hypothetical — the two copies have already drifted once. The
 * server types `families[].family` and `escapes[].family` with the `Family`
 * union; the web copy widened both to `string`. That drift is benign (the web
 * side accepts a superset), which is exactly why nobody caught it. The next one
 * may not be.
 *
 * So this test pins the shape the dashboard reads: every field it renders, by
 * name and type. It deliberately asserts NO numeric values — those are gated by
 * `policy-eval.test.ts` and `security-benchmark.test.ts`, and duplicating them
 * here would mean two places to update when the policy improves.
 */

const service = {
  listAgents: () => [],
  systemInfo: async () => ({}),
} as unknown as AgentService;

async function fetchSummary(): Promise<Record<string, unknown>> {
  const app = await createApp(
    loadConfig({ NODE_ENV: "test", APP_AUTH_TOKEN: "a-strong-test-token" }),
    service,
  );
  try {
    const response = await app.inject({
      method: "GET",
      url: "/api/evaluation",
      headers: { authorization: "Bearer a-strong-test-token" },
    });
    expect(response.statusCode).toBe(200);
    return response.json() as Record<string, unknown>;
  } finally {
    await app.close();
  }
}

describe("GET /api/evaluation payload contract", () => {
  /**
   * Asserts PRESENCE of every field the dashboard reads, not key-set equality.
   *
   * The documented contract is that additive fields are safe and renames are
   * not, so the test has to be shaped the same way. An exact `toEqual` on the
   * key set fails on every addition, which is not a contract violation - and it
   * did: `main` added five provenance fields to `policy` and this test failed
   * while the dashboard was perfectly fine. A missing required key still fails,
   * which is the rename detection this exists for.
   */
  function expectHasAll(actual: object, required: string[], where: string): void {
    const keys = new Set(Object.keys(actual));
    const missing = required.filter((key) => !keys.has(key));
    expect(missing, where + " lost field(s) the dashboard reads").toEqual([]);
  }

  it("returns every top-level field the dashboard reads", async () => {
    const body = await fetchSummary();
    expectHasAll(
      body,
      [
        "benign",
        "corpusSize",
        "escapes",
        "falsePositiveRate",
        "families",
        "generatedAt",
        "headline",
        "latency",
        "policy",
        "secrets",
      ],
      "payload",
    );
  });

  it("keeps the nested objects at the shape the dashboard destructures", async () => {
    const body = await fetchSummary();

    expectHasAll(
      body.headline as object,
      ["attackBlockRate", "attacks", "baselineEscapeRate", "escaped", "unsafeActionEscapeRate"],
      "headline",
    );
    expectHasAll(body.secrets as object, ["attacks", "baselineLeaks", "leaks"], "secrets");
    expectHasAll(
      body.policy as object,
      ["coreRecall", "evasionRecall", "f1", "precision"],
      "policy",
    );
  });

  it("types every scalar the dashboard formats", async () => {
    const body = await fetchSummary();
    expect(typeof body.generatedAt).toBe("string");
    expect(Number.isFinite(body.corpusSize)).toBe(true);
    expect(Number.isFinite(body.falsePositiveRate)).toBe(true);
    expect(Number.isFinite(body.benign)).toBe(true);
    for (const [key, value] of Object.entries(body.headline as Record<string, unknown>)) {
      expect(Number.isFinite(value), "headline." + key).toBe(true);
    }
    for (const [key, value] of Object.entries(body.policy as Record<string, unknown>)) {
      expect(Number.isFinite(value), "policy." + key).toBe(true);
    }
  });

  it("keeps latency additive: p50/p95/mean required, p99 optional", async () => {
    const body = await fetchSummary();
    const latency = body.latency as Record<string, unknown>;

    // The three the web copy declares as required must always be present.
    for (const field of ["p50", "p95", "mean"]) {
      expect(Number.isFinite(latency[field]), field).toBe(true);
    }
    // p99 is the new field. It is optional in both interfaces, so the contract
    // is "absent or a number" — never "present and a string", and never
    // required, which would break the hand-copied web interface.
    if ("p99" in latency) {
      expect(Number.isFinite(latency.p99)).toBe(true);
    }
    // p99 must stay genuinely optional. An exact key-set assertion here made it
    // required in practice - the contract says "absent or a number", so absence
    // has to pass. The required three are checked above; a rename of any of them
    // still fails there.
    for (const key of Object.keys(latency)) {
      expect(["p50", "p95", "p99", "mean"], "unexpected latency field " + key).toContain(key);
    }
  });

  it("returns families and escapes as arrays of the declared element shape", async () => {
    const body = await fetchSummary();

    const families = body.families as Record<string, unknown>[];
    expect(Array.isArray(families)).toBe(true);
    expect(families.length).toBeGreaterThan(0);
    for (const family of families) {
      expect(Object.keys(family).sort()).toEqual(["attacks", "escaped", "family"].sort());
      expect(typeof family.family).toBe("string");
      expect(Number.isFinite(family.attacks)).toBe(true);
      expect(Number.isFinite(family.escaped)).toBe(true);
    }

    const escapes = body.escapes as Record<string, unknown>[];
    expect(Array.isArray(escapes)).toBe(true);
    for (const escape of escapes) {
      expect(Object.keys(escape).sort()).toEqual(["family", "id"].sort());
      expect(typeof escape.id).toBe("string");
      expect(typeof escape.family).toBe("string");
    }
  });

  it("serialises to JSON without losing or aliasing a field", async () => {
    // The dashboard receives this over the wire, so the contract is the JSON
    // round-trip, not the in-process object.
    const body = await fetchSummary();
    expect(JSON.parse(JSON.stringify(body))).toEqual(body);
  });
});
