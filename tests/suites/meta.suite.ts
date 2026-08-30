/**
 * Meta suite: guards on the suite's own inputs, so the published numbers stay
 * honest. Two checks:
 *
 *   1. Corpus freshness — tests/cases/past-examples.json is a generated
 *      snapshot of the canonical POLICY_CORPUS. If the corpus grew (or was
 *      pruned) and nobody regenerated the snapshot, the suite would quietly
 *      measure stale data that omits the newest bypasses; fail loudly instead
 *      (regenerate with `npm run import:past -w @sentinel/evaluation`).
 *   2. Threat-coverage ids — tests/docs/threat-coverage.json hand-lists
 *      TM-AGENT-* and CTRL-* ids; every id must resolve against
 *      THREAT_REGISTER so the doc cannot drift into fantasy ids.
 */

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { POLICY_CORPUS } from "../../apps/server/src/evaluation/policy-corpus.js";
import { THREAT_REGISTER } from "../../apps/server/src/threat/threat-model.js";
import { gitRevision } from "../lib/harness.js";
import type { SuiteModule } from "./suite.js";
import type { CaseVerdict } from "../lib/types.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));

export const META_SUITE: SuiteModule = {
  id: "meta",
  name: "Suite meta-guards (corpus freshness, coverage ids)",
  async run() {
    const verdicts: CaseVerdict[] = [];

    // 1. Corpus snapshot freshness vs the live canonical corpus.
    const past = JSON.parse(
      await readFile(path.join(HERE, "..", "cases", "past-examples.json"), "utf8"),
    ) as { corpusSize?: unknown; revision?: unknown };
    const recorded = past.corpusSize;
    const live = POLICY_CORPUS.length;
    const fresh = typeof recorded === "number" && recorded === live;
    verdicts.push({
      caseId: "corpus-snapshot-fresh",
      decision: "n/a",
      rule: null,
      matchesExpected: fresh,
      note: fresh
        ? "past-examples.json corpusSize " + recorded + " matches live POLICY_CORPUS"
        : "STALE SNAPSHOT: past-examples.json records corpusSize " + String(recorded) +
          ", live POLICY_CORPUS is " + live + " — rerun `npm run import:past -w @sentinel/evaluation`",
    });

    // 2. threat-coverage.json ids must resolve against the register.
    const cov = JSON.parse(
      await readFile(path.join(HERE, "..", "docs", "threat-coverage.json"), "utf8"),
    ) as { coverage: { threatIds?: string[]; controls?: string[] }[] };
    const threatIds = new Set(THREAT_REGISTER.map((t) => t.id));
    const ctrlIds = new Set(THREAT_REGISTER.flatMap((t) => t.controls.map((c) => c.id)));
    const missing: string[] = [];
    for (const entry of cov.coverage) {
      for (const id of entry.threatIds ?? []) {
        if (!threatIds.has(id)) missing.push("threat " + id);
      }
      for (const id of entry.controls ?? []) {
        if (!ctrlIds.has(id)) missing.push("control " + id);
      }
    }
    verdicts.push({
      caseId: "threat-coverage-ids-resolve",
      decision: "n/a",
      rule: null,
      matchesExpected: missing.length === 0,
      note: missing.length === 0
        ? "all threat-coverage ids resolve against THREAT_REGISTER"
        : "unknown coverage id(s): " + missing.join(", "),
    });

    const passed = verdicts.filter((v) => v.matchesExpected).length;
    return {
      suite: "meta",
      profileId: "meta",
      profileName: "Suite meta-guards (corpus freshness, coverage ids)",
      runAt: new Date().toISOString(),
      revision: gitRevision(),
      totals: {
        cases: verdicts.length,
        passed,
        failed: verdicts.length - passed,
        malicious: 0,
        benign: 0,
        maliciousBlocked: 0,
        maliciousEscaped: 0,
        benignBlocked: 0,
        detectedMalicious: 0,
        attackBlockRate: 0,
        escapeRate: 0,
        falsePositiveRate: 0,
        detectionRate: 0,
      },
      byTag: {},
      byCategory: {},
      verdicts,
    };
  },
};
