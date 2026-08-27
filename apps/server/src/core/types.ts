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
export type MessageRole = "user" | "assistant";

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
  role: MessageRole;
  content: string;
  createdAt: string;
}

export interface RunUsage {
  inputTokens?: number;
  cachedInputTokens?: number;
  outputTokens?: number;
}

export interface AgentRun {
  id: string;
  agentId: string;
  status: RunStatus;
  prompt: string;
  output: string | null;
  error: string | null;
  usage: RunUsage | null;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
}

export interface PolicyDecision {
  id: string;
  agentId: string;
  runId: string;
  rule: string;
  /** Redacted before storage; never the raw command. */
  command: string;
  detail: string;
  /**
   * False when the policy was in monitor mode: the command was observed and
   * recorded but allowed to proceed. Monitor decisions are how a policy change
   * is trialled against real traffic before it starts denying anything.
   */
  enforced: boolean;
  decidedAt: string;
}

export type ApprovalStatus = "pending" | "approved" | "denied";

export interface ApprovalRequest {
  id: string;
  agentId: string;
  /** The run that was held. */
  runId: string;
  /** Original prompt, kept so an approval can resume the task. */
  prompt: string;
  rule: string;
  command: string;
  detail: string;
  /** Hosts an approval would grant a run-scoped grant for. */
  hosts: string[];
  status: ApprovalStatus;
  requestedAt: string;
  /** Named human who resolved it. No real identity in this POC — a label. */
  resolvedBy: string | null;
  /** Why the human approved or denied. Recorded to detect rubber-stamping. */
  decisionReason: string | null;
  resolvedAt: string | null;
  /** The continuation run created when approved, if any. */
  continuationRunId: string | null;
}

export interface Database {
  version: 1;
  agents: Agent[];
  messages: Message[];
  runs: AgentRun[];
  policyEvents: PolicyDecision[];
  approvals: ApprovalRequest[];
}

export interface CreateAgentInput {
  name: string;
  description?: string | undefined;
  instructions?: string | undefined;
}

export interface UpdateAgentInput {
  name?: string | undefined;
  description?: string | undefined;
  instructions?: string | undefined;
}

export interface RunnerResult {
  output: string;
  threadId: string | null;
  usage: RunUsage | null;
  /**
   * Policy denials observed during a Run that completed anyway, which only
   * happens in monitor mode. In enforce mode a denial ends the Run instead.
   */
  violations?: PolicyObservation[];
}

export interface PolicyObservation {
  rule: string;
  command: string;
  detail: string;
}

export interface RunnerRequest {
  agentId: string;
  workspacePath: string;
  prompt: string;
  threadId: string | null;
  /**
   * Hosts allowed for this run only, on top of the standing allowlist. Set when
   * a human has approved a held run; scoped to this single execution and never
   * persisted to config.
   */
  extraAllowedHosts?: string[];
}

export interface AgentRunner {
  run(request: RunnerRequest): Promise<RunnerResult>;
  cancel(agentId: string): Promise<boolean>;
  isAvailable(): Promise<boolean>;
}
