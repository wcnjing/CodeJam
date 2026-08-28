/**
 * Shared types for the Sentinel middleware pentest suite.
 *
 * A `TestCase` is one shell command with a ground-truth label. The same catalog
 * is run against every middleware layer (baseline, command policy, redaction,
 * step budget, human approval, monitor mode, config invariants) and against the
 * whole stack (regression), so the layers can be compared individually and as
 * a whole — the AGENTS.md testing requirement.
 */

export type CaseLabel = "malicious" | "benign";
export type ExpectedDecision = "deny" | "allow";

export interface TestCase {
  /** Stable unique id, e.g. `corpus-direct-egress-0` or `rt-quote-split`. */
  id: string;
  /** The raw shell command, exactly as an agent would run it. */
  command: string;
  /** Ground truth: does this command intend harm? */
  label: CaseLabel;
  /** What a perfect middleware stack would do with this command. */
  expected: ExpectedDecision;
  /** Tag ids from TAG_VOCABULARY (bypass families). */
  tags: string[];
  /** Human grouping for per-category scorecards. */
  category: string;
  /**
   * Evaluate in the `/bin/bash -lc '<command>'` form Codex actually emits.
   * Live-observed commands always arrive wrapped, and the rules must match
   * the wrapped form too (defect #8 in docs/POLICY_EVALUATION.md).
   */
  wrapped?: boolean | undefined;
  /** Provenance: which corpus / tool produced this case. */
  source?: string | undefined;
  /** Threat-register ids this case exercises (TM-AGENT-00x). */
  threatIds?: string[] | undefined;
  /** Which middleware layers this case specifically targets. */
  middleware?: string[] | undefined;
  note?: string | undefined;
}

/** One run of one case against one middleware profile. */
export interface CaseVerdict {
  caseId: string;
  decision: "allow" | "deny" | "n/a";
  rule: string | null;
  /** True when the layer behaved as the case's `expected` demands. */
  matchesExpected: boolean;
  /** Redaction layer: did a protected secret survive into the output? */
  leak?: boolean | undefined;
  /** Approval layer: is this denial reviewable by a human? */
  reviewable?: boolean | null;
  /** Budget layer: did this run trip the step budget? */
  terminated?: boolean | undefined;
  note?: string | undefined;
}

export interface SuiteTotals {
  cases: number;
  passed: number;
  failed: number;
  malicious: number;
  benign: number;
  maliciousBlocked: number;
  maliciousEscaped: number;
  benignBlocked: number;
  attackBlockRate: number;
  escapeRate: number;
  falsePositiveRate: number;
}

export interface BucketScore {
  total: number;
  passed: number;
  rate: number;
}

export interface SuiteResult {
  suite: string;
  profileId: string;
  profileName: string;
  runAt: string;
  /** git describe of the code under test, when available. */
  revision: string;
  totals: SuiteTotals;
  byTag: Record<string, BucketScore>;
  byCategory: Record<string, BucketScore>;
  verdicts: CaseVerdict[];
  perf?: PerfReport;
}

export interface PerfSample {
  profileId: string;
  profileName: string;
  metric: string;
  samples: number;
  meanMicroseconds: number;
  p50Microseconds: number;
  p95Microseconds: number;
  opsPerSecond: number;
  /** Breakdown by command length bucket, when applicable. */
  byLength?: Record<string, { samples: number; meanMicroseconds: number }> | undefined;
}

export interface PerfReport {
  generatedAt: string;
  samples: PerfSample[];
}
