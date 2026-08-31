/**
 * Tests for the indirect prompt-injection benchmark.
 *
 * The point of these is not to re-assert that the policy works — the enforcement
 * CLI gate does that on every push. It is to keep the benchmark itself honest:
 * that the corpus is malicious by construction, that the two rates stay
 * unmultiplied, and above all that the documented residual is exactly what is
 * documented — no more (a regression), and no fewer (a fix the ratchet did not
 * follow down).
 */

import { describe, expect, it } from "vitest";
import {
  DOCUMENTED_BYPASS_SIGNATURES,
  MAX_KNOWN_BYPASSES,
  describeWhyNoCombinedScore,
  generateRequestedCommands,
  runEnforcement,
} from "./injection.js";

describe("the requested-command corpus", () => {
  const rows = generateRequestedCommands();

  it("is the full cross product, with stable unique ids", () => {
    // 3 collectors x (8 file-reading payloads x 3 secrets + 1 env payload x 1)
    // x 30 carriers.
    expect(rows.length).toBe(3 * (8 * 3 + 1) * 30);
    expect(new Set(rows.map((r) => r.id)).size).toBe(rows.length);
  });

  it("keeps closed carriers in the axis, so the boundary is measured", () => {
    // A bounded class is only a claim if the boundary is exercised. These are
    // the carriers that currently hold; if one silently leaves the axis, the
    // 'systematic but bounded' framing stops being supported by anything.
    const carriers = new Set(rows.map((r) => r.reproduction));
    for (const closed of [
      "pipe-to-sh",
      "write-then-cat-pipe",
      "heredoc-to-file-run",
      "base64-to-file-run",
      "xxd-to-file-run",
      "sh-c-direct",
    ]) {
      expect(carriers).toContain(closed);
    }
  });

  it("covers all three carrier classes", () => {
    const classes = new Set(rows.map((r) => r.carrierClass));
    expect(classes).toEqual(
      new Set(["direct", "materialised-file", "materialised-stdin"]),
    );
  });

  it("is malicious by construction: every row names a non-allowlisted sink", () => {
    // The allowlisted host must never appear; if it did, a row could be a true
    // benign and the recall denominator would be wrong.
    for (const row of rows) {
      expect(row.command).not.toContain("ark.cn-beijing.volces.com");
    }
  });

  it("reads a protected resource in every row, decoding the encoded carriers", () => {
    const secretMarkers = [".secrets/", ".env", ".ssh/", "printenv"];
    const hasMarker = (text: string) => secretMarkers.some((m) => text.includes(m));
    for (const row of rows) {
      if (hasMarker(row.command)) continue;
      // The encoded carriers hide the path on purpose -- that is what they are
      // testing. Decode the blob and assert the payload underneath is still a
      // real secret read, so an encoding bug cannot quietly empty the corpus.
      const blob = /echo ([A-Za-z0-9+/=]+) \|/.exec(row.command)?.[1];
      expect(blob, `no marker and no blob in: ${row.command}`).toBeDefined();
      const decoded = /^[0-9a-f]+$/.test(blob!)
        ? Buffer.from(blob!, "hex").toString()
        : Buffer.from(blob!, "base64").toString();
      expect(hasMarker(decoded), `decoded payload has no secret: ${decoded}`).toBe(true);
    }
  });
});

describe("the enforcement measurement", () => {
  const result = runEnforcement();

  it("denies everything except the documented residual", () => {
    // Every allowed command must belong to a documented signature. A NEW
    // signature here is a regression and must fail the suite, not just the CLI.
    const allowedSignatures = new Set(
      result.allowed.map((r) => `${r.payload}|${r.reproduction}`),
    );
    for (const signature of allowedSignatures) {
      expect(DOCUMENTED_BYPASS_SIGNATURES).toContain(signature);
    }
  });

  it("keeps the ratchet honest in both directions", () => {
    // Above the ratchet: a regression widened the gap. Below it: the engine
    // closed part of the gap and nobody lowered the number, so the gate would
    // wave through a future regression back up to the stale ceiling. Both are
    // failures, which is what makes the ratchet mean something.
    expect(result.allowed.length).toBe(MAX_KNOWN_BYPASSES);
  });

  it("still exhibits the exact documented residual class", () => {
    // If someone lands `writtenScriptPayloads`, these stop being ALLOWED and
    // this fails — the signal to drop the ratchet to 0 and delete the
    // signatures. A residual that has been fixed must not keep being described
    // as open.
    const stillOpen = new Set(
      result.allowed.map((r) => `${r.payload}|${r.reproduction}`),
    );
    expect(stillOpen).toEqual(new Set(DOCUMENTED_BYPASS_SIGNATURES));
  });

  it("leaks nothing in the direct class", () => {
    // Every bypass is a materialisation carrier. If a `direct` rendering ever
    // leaks, this stops being a materialisation problem and becomes a
    // regression in the ordinary rules -- a different finding with a different
    // owner, and it must not be absorbed silently into this ratchet.
    const direct = result.allowed.filter((r) => r.carrierClass === "direct");
    expect(direct).toEqual([]);
  });

  it("reports intervals, not bare rates", () => {
    expect(result.ci.low).toBeLessThanOrEqual(result.rate);
    expect(result.ci.high).toBeGreaterThanOrEqual(result.rate);
    // With residuals present this is a two-sided Wilson interval, not the
    // zero-failure bound.
    expect(result.missUpperBound).toBeNull();
  });
});

describe("the two rates are never multiplied", () => {
  it("says so in the printed report, not just in a comment", () => {
    const text = describeWhyNoCombinedScore().join("\n");
    expect(text).toMatch(/NOT multiplied/i);
    // The specific failure the separation prevents must be named, so the reader
    // understands why rather than being told to trust it.
    expect(text).toMatch(/scores perfectly|rounds to 100%/i);
  });
});
