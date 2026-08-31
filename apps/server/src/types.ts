import type { CapabilityRequest } from "./capabilities.js";

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
  /**
   * Capabilities the command requested, in the vocabulary the policy decides
   * on. Lets the operator timeline say what was attempted — "NETWORK_EGRESS to
   * attacker.example" — rather than only which rule matched.
   */
  capabilities?: CapabilityRequest[];
  decidedAt: string;
}

export type ApprovalStatus = "pending" | "approved" | "denied";

export interface ApprovalRequest {
  id: string;
  agentId: string;
  /** The run that was held. */
  runId: string;
  /** Prompt associated with the held run, kept so a continuation can resume it. */
  prompt: string;
  rule: string;
  command: string;
  detail: string;
  /** Hosts an approval would grant a run-scoped grant for. */
  hosts: string[];
  status: ApprovalStatus;
  requestedAt: string;
  /**
   * Id of whoever resolved it. For `resolvedByAttribution: "credential"` —
   * everything this code writes — it is the authenticated principal derived
   * from the request's credential and is never client-supplied. Read it
   * together with the attribution: records migrated from schema v1 carry a name
   * the client asserted, and the two are otherwise indistinguishable.
   */
  resolvedBy: string | null;
  /**
   * Where `resolvedBy` came from, so a stored decision says for itself whether
   * its approver is trustworthy. Null while pending. "self-asserted" appears
   * only on records migrated from schema v1, when the approver was a free-text
   * body field; nothing writes it at runtime.
   */
  resolvedByAttribution: ApproverAttribution | null;
  /** Why the human approved or denied. Recorded to detect rubber-stamping. */
  decisionReason: string | null;
  resolvedAt: string | null;
  /** The continuation run created when approved, if any. */
  continuationRunId: string | null;
  /**
   * Hosts this approval added to the STANDING allowlist (the store-backed
   * override list), present only when the approver chose "approve and widen".
   * Absent on pre-v4 records, which predate the widening option; null on every
   * record written since. Recorded so the audit trail can say for itself that
   * a decision was also a permanent config change.
   */
  allowlistWidened?: string[] | null;
}

/**
 * How an approval's `resolvedBy` was established. Only "credential" is ever
 * written now; "self-asserted" exists to label pre-v2 records honestly rather
 * than let them pass as authenticated.
 */
export type ApproverAttribution = "credential" | "self-asserted";

/**
 * Frozen history: the shape a pre-v2 release wrote. It exists so a migration
 * step is typed against what a record actually had at the time, rather than
 * against today's `Database` with fields that did not exist yet. Never widen
 * this to fix a compile error in a newer migration — add the next step instead.
 */
export interface DatabaseV1 {
  version: 1;
  agents: Agent[];
  messages: Message[];
  runs: AgentRun[];
  policyEvents: PolicyDecision[];
  approvals: Omit<ApprovalRequest, "resolvedByAttribution">[];
}

/**
 * Frozen history: the shape v2 wrote, with policy events inside the blob. Kept
 * for the same reason DatabaseV1 is -- the v2->v3 migration step is typed
 * against what a v2 record actually had, not against today's Database. Never
 * widen this to fix a compile error in a newer migration; add the next step.
 */
export interface DatabaseV2 {
  version: 2;
  agents: Agent[];
  messages: Message[];
  runs: AgentRun[];
  policyEvents: PolicyDecision[];
  approvals: ApprovalRequest[];
}

/**
 * Frozen history: the shape v3 wrote. Kept for the same reason the other
 * versions are — the v3->v4 migration step is typed against what a v3 record
 * actually had, not against today's `Database`. Never widen this to fix a
 * compile error in a newer migration; add the next step.
 */
export interface DatabaseV3 {
  version: 3;
  agents: Agent[];
  messages: Message[];
  runs: AgentRun[];
  policyEvents: PolicyDecision[];
  approvals: ApprovalRequest[];
}

export interface Database {
  /**
   * 4: the store now carries a standing, operator-editable allowlist override
   * (`allowlist`) on top of the immutable POLICY_ALLOWED_HOSTS config baseline.
   * Writes to it are themselves governance events: the only writers are the
   * allowlist API and an approval that explicitly chooses to widen.
   */
  version: 4;
  agents: Agent[];
  messages: Message[];
  runs: AgentRun[];
  policyEvents: PolicyDecision[];
  approvals: ApprovalRequest[];
  /** Hosts allowed on top of the config baseline, editable in the UI. */
  allowlist: string[];
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
  /** Capabilities the observed command requested, carried into evidence. */
  capabilities?: CapabilityRequest[];
}

export interface RunnerRequest {
  agentId: string;
  workspacePath: string;
  prompt: string;
  threadId: string | null;
  /**
   * Hosts allowed for this run only, on top of the standing allowlist. Set when
   * a human has approved a held run; scoped to this single execution and never
   * persisted to config. The service merges the store-backed allowlist override
   * in here too, so a runner consuming this field sees the FULL effective
   * allowlist (config baseline + overrides + run-scoped grant).
   */
  extraAllowedHosts?: string[];
}

export interface AgentRunner {
  run(request: RunnerRequest): Promise<RunnerResult>;
  cancel(agentId: string): Promise<boolean>;
  isAvailable(): Promise<boolean>;
}
