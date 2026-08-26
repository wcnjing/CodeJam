import { randomUUID } from "node:crypto";
import type { AppConfig } from "./config.js";
import { isArkConfigured } from "./config.js";
import {
  BudgetExceededError,
  HttpError,
  PolicyViolationError,
  RunCancelledError,
} from "./errors.js";
import { isReviewableRule } from "./command-policy.js";
import { JsonStore } from "./store.js";
import type {
  Agent,
  AgentRun,
  AgentRunner,
  CreateAgentInput,
  ApprovalRequest,
  Message,
  PolicyDecision,
  PolicyObservation,
  UpdateAgentInput,
} from "./types.js";
import { WorkspaceManager } from "./workspace.js";

const now = () => new Date().toISOString();

export class AgentService {
  private readonly activeExecutions = new Map<string, Promise<void>>();
  private readonly cancellationRequests = new Set<string>();

  constructor(
    private readonly config: AppConfig,
    private readonly store: JsonStore,
    private readonly workspaces: WorkspaceManager,
    private readonly runner: AgentRunner,
  ) {}

  async initialize(): Promise<void> {
    await this.store.initialize();
    await this.workspaces.initialize();
    await this.store.mutate((database) => {
      for (const run of database.runs) {
        if (run.status === "queued" || run.status === "running") {
          run.status = "cancelled";
          run.error = "Server restarted while this run was active";
          run.completedAt = now();
        }
      }
      for (const agent of database.agents) {
        if (agent.status === "busy") {
          agent.status = "ready";
          agent.updatedAt = now();
        }
      }
    });
  }

  listAgents(): Agent[] {
    return this.store
      .snapshot()
      .agents.sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  }

  getAgent(id: string): Agent {
    const agent = this.store.snapshot().agents.find((item) => item.id === id);
    if (!agent) {
      throw new HttpError(404, "Agent not found");
    }
    return agent;
  }

  async createAgent(input: CreateAgentInput): Promise<Agent> {
    const timestamp = now();
    const id = randomUUID();
    const agent: Agent = {
      id,
      name: input.name.trim(),
      description: input.description?.trim() ?? "",
      instructions: input.instructions?.trim() ?? "",
      status: "ready",
      workspacePath: this.workspaces.workspacePath(id),
      codexThreadId: null,
      lastError: null,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    await this.workspaces.create(agent);
    await this.store.mutate((database) => database.agents.push(agent));
    return agent;
  }

  async updateAgent(id: string, input: UpdateAgentInput): Promise<Agent> {
    const current = this.getAgent(id);
    if (current.status === "busy") {
      throw new HttpError(409, "Stop the active run before editing this Agent");
    }
    const updated = await this.store.mutate((database) => {
      const agent = database.agents.find((item) => item.id === id);
      if (!agent) {
        throw new HttpError(404, "Agent not found");
      }
      if (agent.status === "busy") {
        throw new HttpError(409, "Stop the active run before editing this Agent");
      }
      if (input.name !== undefined) agent.name = input.name.trim();
      if (input.description !== undefined) agent.description = input.description.trim();
      if (input.instructions !== undefined) agent.instructions = input.instructions.trim();
      agent.lastError = null;
      agent.updatedAt = now();
      return structuredClone(agent);
    });
    await this.workspaces.writeInstructions(updated);
    return updated;
  }

  async deleteAgent(id: string): Promise<{ archivedWorkspace: string }> {
    const agent = this.getAgent(id);
    await this.cancelExecution(id);
    const archivedWorkspace = await this.workspaces.archive(agent);
    await this.store.mutate((database) => {
      database.agents = database.agents.filter((item) => item.id !== id);
      database.messages = database.messages.filter((item) => item.agentId !== id);
      database.runs = database.runs.filter((item) => item.agentId !== id);
      // Delete the Agent's safety evidence too, so it is not orphaned in the store.
      database.policyEvents = database.policyEvents.filter((item) => item.agentId !== id);
      database.approvals = database.approvals.filter((item) => item.agentId !== id);
    });
    return { archivedWorkspace };
  }

  async startAgent(id: string): Promise<Agent> {
    return this.setStatus(id, "ready");
  }

  async stopAgent(id: string): Promise<Agent> {
    this.getAgent(id);
    await this.cancelExecution(id);
    return this.setStatus(id, "stopped");
  }

  getMessages(agentId: string): Message[] {
    this.getAgent(agentId);
    return this.store
      .snapshot()
      .messages.filter((message) => message.agentId === agentId)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  getRun(runId: string): AgentRun {
    const run = this.store.snapshot().runs.find((item) => item.id === runId);
    if (!run) {
      throw new HttpError(404, "Run not found");
    }
    return run;
  }

  getRuns(agentId: string): AgentRun[] {
    this.getAgent(agentId);
    return this.store
      .snapshot()
      .runs.filter((run) => run.agentId === agentId)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  }

  getPolicyEvents(agentId: string): PolicyDecision[] {
    this.getAgent(agentId);
    return this.store
      .snapshot()
      .policyEvents.filter((event) => event.agentId === agentId)
      .sort((left, right) => right.decidedAt.localeCompare(left.decidedAt));
  }

  listApprovals(agentId?: string): ApprovalRequest[] {
    return this.store
      .snapshot()
      .approvals.filter((approval) => !agentId || approval.agentId === agentId)
      .sort((left, right) => right.requestedAt.localeCompare(left.requestedAt));
  }

  getApproval(id: string): ApprovalRequest {
    const approval = this.store.snapshot().approvals.find((item) => item.id === id);
    if (!approval) throw new HttpError(404, "Approval request not found");
    return approval;
  }

  /**
   * Resolves a held run. A human with the command and its reason in front of
   * them approves or denies it; the decision and the named actor are recorded
   * so override rates can be reviewed for rubber-stamping.
   *
   * Approval grants a run-scoped host grant for exactly the hosts the
   * denied command named, then resumes the original task as a new run. The
   * grant is never written to config and applies to that one run only.
   */
  async resolveApproval(
    id: string,
    decision: "approve" | "deny",
    actor: string,
    reason: string,
  ): Promise<{ approval: ApprovalRequest; continuationRun: AgentRun | null }> {
    const trimmedActor = actor.trim();
    if (!trimmedActor) {
      throw new HttpError(400, "An approver name is required to record the decision");
    }
    const trimmedReason = reason.trim();
    if (!trimmedReason) {
      throw new HttpError(400, "A reason is required so every decision records why");
    }

    if (decision === "deny") {
      const denied = await this.store.mutate((database) => {
        const approval = database.approvals.find((item) => item.id === id);
        if (!approval) throw new HttpError(404, "Approval request not found");
        if (approval.status !== "pending") {
          throw new HttpError(409, "This request was already " + approval.status);
        }
        approval.status = "denied";
        approval.resolvedBy = trimmedActor;
        approval.decisionReason = trimmedReason;
        approval.resolvedAt = now();
        return structuredClone(approval);
      });
      return { approval: denied, continuationRun: null };
    }

    // Approve: flip the approval, create the continuation run, and mark the
    // Agent busy in ONE mutation. Either all three commit or none do, so a
    // busy/stopped Agent leaves the approval pending and retryable — never
    // stranded as "approved" with no run. This also serializes concurrent
    // resolutions through the single-writer store.
    const timestamp = now();
    const run: AgentRun = {
      id: randomUUID(),
      agentId: "",
      status: "queued",
      prompt: "",
      output: null,
      error: null,
      usage: null,
      startedAt: null,
      completedAt: null,
      createdAt: timestamp,
    };
    const committed = await this.store.mutate((database) => {
      const approval = database.approvals.find((item) => item.id === id);
      if (!approval) throw new HttpError(404, "Approval request not found");
      if (approval.status !== "pending") {
        throw new HttpError(409, "This request was already " + approval.status);
      }
      const agent = database.agents.find((item) => item.id === approval.agentId);
      if (!agent) throw new HttpError(404, "Agent not found");
      if (agent.status === "busy") {
        throw new HttpError(409, "This Agent is already running");
      }
      if (agent.status === "stopped") {
        throw new HttpError(409, "Start the Agent before approving");
      }
      run.agentId = approval.agentId;
      run.prompt = approval.prompt;
      database.runs.push(run);
      // No duplicate user message: the held run already recorded the operator's
      // request. The continuation is a system-initiated resume of that request.
      const agentSnapshot = structuredClone(agent);
      agent.status = "busy";
      agent.lastError = null;
      agent.updatedAt = timestamp;
      approval.status = "approved";
      approval.resolvedBy = trimmedActor;
      approval.decisionReason = trimmedReason;
      approval.resolvedAt = now();
      approval.continuationRunId = run.id;
      return { approval: structuredClone(approval), agentSnapshot, hosts: approval.hosts };
    });

    // Grant is scoped to this one run (isGrantRun=true), so a re-denial hard-blocks.
    const execution = this.executeRun(committed.agentSnapshot, run, committed.hosts, true);
    this.activeExecutions.set(committed.agentSnapshot.id, execution);
    void execution
      .finally(() => {
        if (this.activeExecutions.get(committed.agentSnapshot.id) === execution) {
          this.activeExecutions.delete(committed.agentSnapshot.id);
        }
      })
      .catch(() => undefined);

    return { approval: committed.approval, continuationRun: run };
  }

  async sendMessage(
    agentId: string,
    prompt: string,
  ): Promise<{ run: AgentRun; message: Message }> {
    if (!isArkConfigured(this.config)) {
      throw new HttpError(
        503,
        "Ark is not configured. Set ARK_API_KEY and ARK_MODEL, then restart.",
      );
    }
    const timestamp = now();
    const runId = randomUUID();
    const run: AgentRun = {
      id: runId,
      agentId,
      status: "queued",
      prompt,
      output: null,
      error: null,
      usage: null,
      startedAt: null,
      completedAt: null,
      createdAt: timestamp,
    };
    const message: Message = {
      id: randomUUID(),
      agentId,
      runId,
      role: "user",
      content: prompt,
      createdAt: timestamp,
    };
    const agentAtStart = await this.store.mutate((database) => {
      const storedAgent = database.agents.find((item) => item.id === agentId);
      if (!storedAgent) {
        throw new HttpError(404, "Agent not found");
      }
      if (storedAgent.status === "stopped") {
        throw new HttpError(409, "Start the Agent before sending a message");
      }
      if (storedAgent.status === "busy") {
        throw new HttpError(409, "This Agent is already running");
      }
      database.runs.push(run);
      database.messages.push(message);
      const snapshot = structuredClone(storedAgent);
      storedAgent.status = "busy";
      storedAgent.lastError = null;
      storedAgent.updatedAt = timestamp;
      return snapshot;
    });
    const execution = this.executeRun(agentAtStart, run);
    this.activeExecutions.set(agentId, execution);
    void execution
      .finally(() => {
        if (this.activeExecutions.get(agentId) === execution) {
          this.activeExecutions.delete(agentId);
        }
      })
      .catch(() => undefined);
    return { run, message };
  }

  async systemInfo(): Promise<Record<string, unknown>> {
    return {
      arkConfigured: isArkConfigured(this.config),
      arkBaseUrl: this.config.arkBaseUrl,
      arkModel: this.config.arkModel || null,
      codexAvailable: await this.runner.isAvailable(),
      codexSandboxMode: this.config.codexSandboxMode,
      runtimeProvider: this.config.runtimeProvider,
      containerEngine:
        this.config.runtimeProvider === "container"
          ? this.config.containerEngine
          : null,
      runtime:
        this.config.runtimeProvider === "container"
          ? "Codex CLI in " + this.config.containerEngine + " Runtime"
          : "Codex CLI in application container",
    };
  }

  private async executeRun(
    agentAtStart: Agent,
    run: AgentRun,
    extraAllowedHosts: string[] = [],
    isGrantRun = false,
  ): Promise<void> {
    await this.store.mutate((database) => {
      const storedRun = database.runs.find((item) => item.id === run.id);
      if (storedRun) {
        storedRun.status = "running";
        storedRun.startedAt = now();
      }
    });
    try {
      if (this.cancellationRequests.has(agentAtStart.id)) {
        throw new RunCancelledError();
      }
      const result = await this.runner.run({
        agentId: agentAtStart.id,
        workspacePath: agentAtStart.workspacePath,
        prompt: run.prompt,
        threadId: agentAtStart.codexThreadId,
        extraAllowedHosts,
      });
      const completedAt = now();
      await this.store.mutate((database) => {
        const storedRun = database.runs.find((item) => item.id === run.id);
        const agent = database.agents.find((item) => item.id === agentAtStart.id);
        if (!storedRun || !agent) return;
        storedRun.status = "completed";
        storedRun.output = result.output;
        storedRun.usage = result.usage;
        storedRun.completedAt = completedAt;
        database.messages.push({
          id: randomUUID(),
          agentId: agent.id,
          runId: run.id,
          role: "assistant",
          content: result.output,
          createdAt: completedAt,
        });
        agent.status = "ready";
        agent.codexThreadId = result.threadId;
        agent.lastError = null;
        agent.updatedAt = completedAt;
        // Monitor mode: the command was denied by policy but allowed to run.
        // Recording it is the whole point of shadow-running a policy change.
        for (const observation of result.violations ?? []) {
          database.policyEvents.push({
            id: randomUUID(),
            agentId: agent.id,
            runId: run.id,
            rule: observation.rule,
            command: observation.command,
            detail: observation.detail,
            ...(observation.capabilities ? { capabilities: observation.capabilities } : {}),
            enforced: false,
            decidedAt: completedAt,
          });
        }
      });
    } catch (error) {
      const completedAt = now();
      const cancelled = error instanceof RunCancelledError;
      const overBudget = error instanceof BudgetExceededError;
      const policyDenied = error instanceof PolicyViolationError;
      // A reviewable denial (by default only network egress) is held for a
      // human, never a secret-access rule — no human may approve exfiltration.
      const held =
        policyDenied &&
        // Structural invariant: only REVIEWABLE_RULES can ever be held, no
        // matter what config says. Secret-access rules are never approvable.
        isReviewableRule((error as PolicyViolationError).rule) &&
        this.config.policyReviewRules.includes((error as PolicyViolationError).rule) &&
        // A grant-run that is denied again is hard-blocked, not held a second
        // time. Keyed off the explicit origin flag, not the host-list length.
        !isGrantRun;
      const blocked = policyDenied && !held;
      const message = error instanceof Error ? error.message : String(error);
      await this.store.mutate((database) => {
        const storedRun = database.runs.find((item) => item.id === run.id);
        const agent = database.agents.find((item) => item.id === agentAtStart.id);
        if (storedRun) {
          storedRun.status = cancelled
            ? "cancelled"
            : held
              ? "held"
              : blocked
                ? "blocked"
                : overBudget
                  ? "terminated"
                  : "failed";
          storedRun.error = message;
          storedRun.completedAt = completedAt;
        }
        if (error instanceof BudgetExceededError) {
          database.policyEvents.push({
            id: randomUUID(),
            agentId: agentAtStart.id,
            runId: run.id,
            rule: "step-budget-exceeded",
            command: "(" + error.observed + " commands; limit " + error.limit + ")",
            detail: error.message,
            enforced: true,
            decidedAt: completedAt,
          });
        }
        if (error instanceof PolicyViolationError) {
          if (blocked) {
            // Written in the same mutation as the run update so evidence and
            // outcome can never disagree.
            database.policyEvents.push({
              id: randomUUID(),
              agentId: agentAtStart.id,
              runId: run.id,
              rule: error.rule,
              command: error.command,
              detail: error.detail,
              ...(error.capabilities.length > 0 ? { capabilities: error.capabilities } : {}),
              enforced: true,
              decidedAt: completedAt,
            });
          }
          if (held) {
            database.approvals.push({
              id: randomUUID(),
              agentId: agentAtStart.id,
              runId: run.id,
              prompt: run.prompt,
              rule: error.rule,
              command: error.command,
              detail: error.detail,
              hosts: error.hosts,
              status: "pending",
              requestedAt: completedAt,
              resolvedBy: null,
              decisionReason: null,
              resolvedAt: null,
              continuationRunId: null,
            });
          }
        }
        // Monitor mode: persist observed near-misses even though the run FAILED
        // (timeout/budget/error) — otherwise monitor evidence would be lost for
        // exactly the suspicious runs that matter most. Skipped in enforce mode,
        // where the blocking violation is already recorded above as enforced.
        if (this.config.policyEnforcement === "monitor") {
          const observed =
            (error as { observations?: PolicyObservation[] })
              .observations ?? [];
          for (const obs of observed) {
            database.policyEvents.push({
              id: randomUUID(),
              agentId: agentAtStart.id,
              runId: run.id,
              rule: obs.rule,
              command: obs.command,
              detail: obs.detail,
              ...(obs.capabilities ? { capabilities: obs.capabilities } : {}),
              enforced: false,
              decidedAt: completedAt,
            });
          }
        }
        if (agent) {
          if (agent.status !== "stopped") {
            // Blocked or held both mean the control worked and the container is
            // gone, so the Agent stays usable. Only an unexpected failure is an
            // error state the operator must clear.
            agent.status =
              cancelled || blocked || held || overBudget ? "ready" : "error";
          }
          agent.lastError =
            cancelled || blocked || held || overBudget ? null : message;
          agent.updatedAt = completedAt;
        }
      });
    }
  }

  private async setStatus(id: string, status: Agent["status"]): Promise<Agent> {
    return this.store.mutate((database) => {
      const agent = database.agents.find((item) => item.id === id);
      if (!agent) {
        throw new HttpError(404, "Agent not found");
      }
      if (status === "ready" && agent.status === "busy") {
        throw new HttpError(409, "Stop the active run before starting this Agent");
      }
      agent.status = status;
      if (status === "ready") agent.lastError = null;
      agent.updatedAt = now();
      return structuredClone(agent);
    });
  }

  private async cancelExecution(agentId: string): Promise<void> {
    this.cancellationRequests.add(agentId);
    try {
      await this.runner.cancel(agentId);
      const execution = this.activeExecutions.get(agentId);
      if (execution) {
        await execution;
      }
    } finally {
      this.cancellationRequests.delete(agentId);
    }
  }
}
