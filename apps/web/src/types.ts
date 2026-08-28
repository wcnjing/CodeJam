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
  createdAt: string;
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
  decidedAt: string;
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
  resolvedBy: string | null;
  decisionReason: string | null;
  resolvedAt: string | null;
  continuationRunId: string | null;
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
    blindsetRecall: number;
    precision: number;
    f1: number;
  };
  latency: { p50: number; p95: number; mean: number };
  families: { family: string; attacks: number; escaped: number }[];
  escapes: { id: string; family: string }[];
}

/** Pentest suite (bypass library) — one on-demand measurement of every layer. */
export interface PentestSuiteSummary {
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
    attackBlockRate: number;
    escapeRate: number;
    falsePositiveRate: number;
  };
  byTag: Record<string, { total: number; passed: number; rate: number }>;
}

export interface PentestPerfSample {
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

export interface PentestResidual {
  caseId: string;
  command: string;
  tags: string[];
  category: string;
}

export interface PentestSummary {
  generatedAt: string;
  revision: string;
  catalogSize: number;
  suites: PentestSuiteSummary[];
  perf: { generatedAt: string; samples: PentestPerfSample[] };
  residuals: { escapes: PentestResidual[]; falsePositives: PentestResidual[] };
  limitations: string[];
}

export interface SystemInfo {
  arkConfigured: boolean;
  arkBaseUrl: string;
  arkModel: string | null;
  codexAvailable: boolean;
  codexSandboxMode: string;
  runtimeProvider: "local-process" | "container";
  containerEngine: string | null;
  runtime: string;
}
