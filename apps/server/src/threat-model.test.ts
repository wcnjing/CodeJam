import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { risk, THREAT_REGISTER } from "./threat-model.js";

/**
 * Makes the threat register self-enforcing.
 *
 * A threat marked `mitigated` must be referenced by at least one `@covers <id>`
 * tag in the test sources — so deleting or renaming the test that proves a
 * control fails this build. This is the line between a verification artifact and
 * a document that merely claims coverage.
 *
 * Honest limitation: this checks that a tagged test EXISTS, not that the tagged
 * test meaningfully exercises every listed control. The tag is a human claim of
 * coverage that the reviewer should still read; the automation prevents silent
 * decay (a deleted test), not a mislabelled one.
 */

const here = path.dirname(fileURLToPath(import.meta.url));

/** All `@covers TM-...` ids declared across the test suite. */
function coveredThreatIds(): Set<string> {
  const ids = new Set<string>();
  for (const file of readdirSync(here)) {
    if (!file.endsWith(".test.ts")) continue;
    const text = readFileSync(path.join(here, file), "utf8");
    for (const match of text.matchAll(/@covers\s+((?:TM-[A-Z]+-\d+\s*)+)/g)) {
      for (const id of match[1]!.trim().split(/\s+/)) ids.add(id);
    }
  }
  return ids;
}

describe("threat register integrity", () => {
  const ids = THREAT_REGISTER.map((t) => t.id);
  const covered = coveredThreatIds();
  const registerIds = new Set(ids);

  it("has unique threat ids", () => {
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("gives every threat an owner, a control, and a review trigger", () => {
    for (const t of THREAT_REGISTER) {
      expect(t.owner, t.id).toBeTruthy();
      expect(t.controls.length, t.id).toBeGreaterThan(0);
      expect(t.reviewTriggers.length, t.id).toBeGreaterThan(0);
    }
  });

  it("keeps residual risk no higher than inherent risk", () => {
    for (const t of THREAT_REGISTER) {
      expect(risk(t.residual), t.id).toBeLessThanOrEqual(risk(t.inherent));
    }
  });

  it("records a residual note for every mitigated threat", () => {
    for (const t of THREAT_REGISTER) {
      if (t.status === "mitigated") expect(t.residualNote.length, t.id).toBeGreaterThan(10);
    }
  });

  it("backs every mitigated threat with at least one real @covers test", () => {
    const unverified = THREAT_REGISTER.filter(
      (t) => t.status === "mitigated" && !covered.has(t.id),
    ).map((t) => t.id);
    expect(unverified, "mitigated threats with no verifying test").toEqual([]);
  });

  it("does not reference threat ids that are not in the register", () => {
    const dangling = [...covered].filter((id) => !registerIds.has(id));
    expect(dangling, "@covers tags pointing at unknown threats").toEqual([]);
  });

  it("does not silently claim coverage for open risks", () => {
    // An open item must NOT be tagged as covered — that would hide a real gap.
    for (const t of THREAT_REGISTER) {
      if (t.status === "open") expect(covered.has(t.id), t.id).toBe(false);
    }
  });

  it("reports a verified-control rate of 100% for mitigated threats", () => {
    const mitigated = THREAT_REGISTER.filter((t) => t.status === "mitigated");
    const verified = mitigated.filter((t) => covered.has(t.id));
    expect(verified.length).toBe(mitigated.length);
  });
});
