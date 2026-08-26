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

/** What an action would do, in the vocabulary the policy decides on. */
export interface CapabilityRequest {
  capability: "NETWORK_EGRESS" | "SECRET_READ";
  /** A hostname, or the label of the protected material. */
  resource: string;
  trusted: boolean;
  via: "network-tool" | "interpreter" | "destination-only" | "protected-material";
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
  latency: { p50: number; p95: number; mean: number };
  families: { family: string; attacks: number; escaped: number }[];
  escapes: { id: string; family: string }[];
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
