export type AgentStatus = "ready" | "busy" | "stopped" | "error";
export type RunStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled"
  | "blocked"
  | "held"
  | "terminated";

export interface Agent {
  id: string;
  name: string;
  description: string;
  instructions: string;
  status: AgentStatus;
  workspacePath: string;
  codexThreadId: string | null;
  lastError: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface Message {
  id: string;
  agentId: string;
  runId: string;
  role: "user" | "assistant";
  content: string;
  createdAt: string;
}

export interface AgentRun {
  id: string;
  agentId: string;
  status: RunStatus;
  prompt: string;
  output: string | null;
  error: string | null;
  usage: {
    inputTokens?: number;
    cachedInputTokens?: number;
    outputTokens?: number;
  } | null;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
  /**
   * Whether this run's network-layer denials could be read back.
   * `collected` -- an empty denial list truly means nothing was refused.
   * `unavailable` -- the broker's log could not be read; an empty list means
   * nothing is known, and the UI must say so rather than imply a clean run.
   * absent -- the run had no broker at all.
   */
  networkEvidence?: "collected" | "unavailable";
}

/** What an action would do, in the vocabulary the policy decides on. */
export interface CapabilityRequest {
  capability: "NETWORK_EGRESS" | "SECRET_READ" | "FILE_WRITE";
  /** A hostname, the label of the protected material, or a write target. */
  resource: string;
  trusted: boolean;
  via:
    | "network-tool"
    | "interpreter"
    | "destination-only"
    | "protected-material"
    | "file-write"
    | "file-write-unresolved";
  /** Recovered from a payload the command would decode or pipe into a shell. */
  decoded?: true;
}

/**
 * A destination the egress broker refused, after the command already ran.
 *
 * Rendered apart from PolicyDecision because it means something different: the
 * policy layer did not recognise this command, and the network contained it
 * anyway. See the run's `networkEvidence` for whether an empty list means
 * "nothing was refused" or "we could not tell".
 */
export interface NetworkDenial {
  id: string;
  agentId: string;
  runId: string;
  host: string;
  port: number;
  reason: string;
  source: "egress-broker";
  observedAt: string;
}

export interface PolicyDecision {
  id: string;
  agentId: string;
  runId: string;
  rule: string;
  command: string;
  detail: string;
  /** False when the policy only observed the command (monitor mode). */
  enforced: boolean;
  /** Capabilities the command requested, for the operator timeline. */
  capabilities?: CapabilityRequest[];
  decidedAt: string;
}

export interface Principal {
  id: string;
}

export interface ApprovalRequest {
  id: string;
  agentId: string;
  runId: string;
  prompt: string;
  rule: string;
  command: string;
  detail: string;
  hosts: string[];
  status: "pending" | "approved" | "denied";
  requestedAt: string;
  /** Whoever resolved it. Trustworthy only when the attribution says so. */
  resolvedBy: string | null;
  /**
   * Where `resolvedBy` came from. "credential" is derived from the request's
   * credential and cannot be client-supplied; "self-asserted" marks a record
   * migrated from the old free-text approver field.
   */
  resolvedByAttribution: "credential" | "self-asserted" | null;
  decisionReason: string | null;
  resolvedAt: string | null;
  continuationRunId: string | null;
  /**
   * Hosts this approval added to the STANDING allowlist (the store-backed
   * override list), present only when the approver chose "approve and widen".
   * Null/absent means the grant stayed run-scoped.
   */
  allowlistWidened?: string[] | null;
}

/**
 * The standing allowlist, split by origin: `config` is the immutable
 * POLICY_ALLOWED_HOSTS baseline (plus Ark's own host and loopback) and
 * `overrides` is the store-backed list the operator edits in the UI — and that
 * an "approve and widen" decision grows.
 */
export interface Allowlist {
  config: string[];
  overrides: string[];
}

export interface EvaluationSummary {
  generatedAt: string;
  corpusSize: number;
  headline: {
    unsafeActionEscapeRate: number;
    baselineEscapeRate: number;
    attackBlockRate: number;
    attacks: number;
    escaped: number;
  };
  secrets: { leaks: number; attacks: number; baselineLeaks: number };
  falsePositiveRate: number;
  benign: number;
  policy: {
    coreRecall: number;
    evasionRecall: number;
    externalReviewRecall: number;
    externalReviewFalsePositiveRate: number;
    /** Sample sizes behind the two rates above; a rate alone is not evidence. */
    externalReviewAttacks: number;
    externalReviewBenign: number;
    /** Retained regressions authored while reading the rules, not independent. */
    internalRedTeam: number;
    precision: number;
    f1: number;
  };
  // Mirrors apps/server/src/evaluation-summary.ts. Hand-duplicated: there is no
  // shared import, so nothing here is checked against the server at build time.
  // p99 is optional on both sides deliberately — see the note on the server copy.
  latency: { p50: number; p95: number; mean: number; p99?: number };
  families: { family: string; attacks: number; escaped: number }[];
  escapes: { id: string; family: string }[];
}

/** Pentest suite (bypass library) — one on-demand measurement of every layer. */
export interface EvaluationSuiteSummary {
  suite: string;
  profileId: string;
  profileName: string;
  totals: {
    cases: number;
    passed: number;
    failed: number;
    malicious: number;
    benign: number;
    maliciousBlocked: number;
    maliciousEscaped: number;
    benignBlocked: number;
    detectedMalicious: number;
    attackBlockRate: number;
    escapeRate: number;
    falsePositiveRate: number;
    detectionRate: number;
  };
  byTag: Record<string, { total: number; passed: number; rate: number }>;
}

export interface EvaluationPerfSample {
  profileId: string;
  profileName: string;
  metric: string;
  samples: number;
  meanMicroseconds: number;
  p50Microseconds: number;
  p95Microseconds: number;
  opsPerSecond: number;
  byLength?: Record<string, { samples: number; meanMicroseconds: number }>;
}

export interface EvaluationResidual {
  caseId: string;
  command: string;
  tags: string[];
  category: string;
}

export interface EvaluationRunSummary {
  generatedAt: string;
  revision: string;
  catalogSize: number;
  suites: EvaluationSuiteSummary[];
  perf: { generatedAt: string; samples: EvaluationPerfSample[] };
  residuals: { escapes: EvaluationResidual[]; falsePositives: EvaluationResidual[] };
  limitations: string[];
}

export interface SystemInfo {
  arkConfigured: boolean;
  arkBaseUrl: string;
  arkModel: string | null;
  codexAvailable: boolean;
  codexSandboxMode: string;
  /** "enforce" | "monitor" — in monitor mode nothing is blocked or held at all. */
  policyEnforcement: string;
  /** Rules whose denials pause for a human instead of blocking outright. */
  policyReviewRules: string[];
  // Mirrors apps/server/src/config.ts. Hand-duplicated with no shared import,
  // so a provider added there and not here is wrong at runtime with a green
  // build - the same hazard documented on EvaluationSummary.latency.
  runtimeProvider: "local-process" | "container" | "replay";
  containerEngine: string | null;
  runtime: string;
}
