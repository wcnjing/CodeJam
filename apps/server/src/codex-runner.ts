import { execFile } from "node:child_process";
import { spawn, type ChildProcess } from "node:child_process";
import { promisify } from "node:util";
import type { AppConfig } from "./config.js";
import { BudgetExceededError, PolicyViolationError, RunCancelledError } from "./errors.js";
import { policyContextFrom, scanCommands, type DetectedViolation } from "./command-policy.js";
import type {
  AgentRunner,
  RunUsage,
  RunnerRequest,
  RunnerResult,
} from "./types.js";

const execFileAsync = promisify(execFile);

export interface ParsedEvents {
  messages: string[];
  threadId: string | null;
  usage: RunUsage | null;
  errors: string[];
  /** Shell commands the Agent executed, in the order Codex reported them. */
  commands: string[];
  /** Item ids already recorded, so a command seen twice is not double-counted. */
  seenCommandIds: Set<string>;
}

/** A fresh accumulator. Both runners build one per Run. */
export function emptyParsedEvents(threadId: string | null): ParsedEvents {
  return {
    messages: [],
    threadId,
    usage: null,
    errors: [],
    commands: [],
    seenCommandIds: new Set(),
  };
}

export function buildCodexArgs(
  request: RunnerRequest,
  sandboxMode: AppConfig["codexSandboxMode"],
  workspacePath = request.workspacePath,
): string[] {
  const args = [
    "exec",
    "--json",
    "--sandbox",
    sandboxMode,
    "--skip-git-repo-check",
    "-C",
    workspacePath,
  ];
  if (request.threadId) {
    args.push("resume", request.threadId, request.prompt);
  } else {
    args.push(request.prompt);
  }
  return args;
}


function readCommand(item: Record<string, unknown>): string | null {
  if (typeof item.command === "string") return item.command;
  if (Array.isArray(item.command)) {
    const parts = item.command.filter((part): part is string => typeof part === "string");
    if (parts.length > 0) return parts.join(" ");
  }
  return null;
}

export function parseCodexEventLine(line: string, parsed: ParsedEvents): void {
  let event: Record<string, unknown>;
  try {
    event = JSON.parse(line) as Record<string, unknown>;
  } catch {
    return;
  }

  if (event.type === "thread.started" && typeof event.thread_id === "string") {
    parsed.threadId = event.thread_id;
  }

  if (
    (event.type === "item.completed" || event.type === "item.started") &&
    event.item &&
    typeof event.item === "object"
  ) {
    const item = event.item as Record<string, unknown>;
    if (
      event.type === "item.completed" &&
      item.type === "agent_message" &&
      typeof item.text === "string"
    ) {
      parsed.messages.push(item.text);
    }
    if (item.type === "command_execution") {
      const command = readCommand(item);
      const id = typeof item.id === "string" ? item.id : null;
      if (command && !(id && parsed.seenCommandIds.has(id))) {
        if (id) parsed.seenCommandIds.add(id);
        parsed.commands.push(command);
      }
    }
  }

  if (event.type === "turn.completed" && event.usage && typeof event.usage === "object") {
    const usage = event.usage as Record<string, unknown>;
    parsed.usage = {
      ...(typeof usage.input_tokens === "number"
        ? { inputTokens: usage.input_tokens }
        : {}),
      ...(typeof usage.cached_input_tokens === "number"
        ? { cachedInputTokens: usage.cached_input_tokens }
        : {}),
      ...(typeof usage.output_tokens === "number"
        ? { outputTokens: usage.output_tokens }
        : {}),
    };
  }

  if (event.type === "error") {
    const message =
      typeof event.message === "string"
        ? event.message
        : typeof event.error === "string"
          ? event.error
          : "Codex reported an unknown error";
    parsed.errors.push(message);
  }
}

export class CodexRunner implements AgentRunner {
  private readonly active = new Map<
    string,
    {
      child: ChildProcess;
      cancelled: boolean;
      timedOut: boolean;
      outputExceeded: boolean;
      violation: DetectedViolation | null;
      budgetExceeded: boolean;
      settled: Promise<void>;
      forceKillTimer: NodeJS.Timeout | null;
    }
  >();

  constructor(private readonly config: AppConfig) {}

  async isAvailable(): Promise<boolean> {
    try {
      await execFileAsync(this.config.codexBin, ["--version"], {
        timeout: 5_000,
        env: this.childEnvironment(),
      });
      return true;
    } catch {
      return false;
    }
  }

  async cancel(agentId: string): Promise<boolean> {
    const active = this.active.get(agentId);
    if (!active) {
      return false;
    }
    active.cancelled = true;
    this.terminate(active);
    await active.settled;
    return true;
  }

  async run(request: RunnerRequest): Promise<RunnerResult> {
    if (this.active.has(request.agentId)) {
      throw new Error("Agent already has an active Codex process");
    }

    const args = buildCodexArgs(request, this.config.codexSandboxMode);
    const child = spawn(this.config.codexBin, args, {
      cwd: request.workspacePath,
      env: this.childEnvironment(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    const settled = new Promise<void>((resolve) => {
      child.once("close", () => resolve());
      child.once("error", () => resolve());
    });
    const active = {
      child,
      cancelled: false,
      timedOut: false,
      outputExceeded: false,
      violation: null as DetectedViolation | null,
      budgetExceeded: false,
      settled,
      forceKillTimer: null as NodeJS.Timeout | null,
    };
    this.active.set(request.agentId, active);

    const parsed = emptyParsedEvents(request.threadId);
    const policyContext = policyContextFrom(
      this.config.arkBaseUrl,
      [...this.config.policyAllowedHosts, ...(request.extraAllowedHosts ?? [])],
      [this.config.arkApiKey],
    );
    let stdout = "";
    let stderr = "";
    let totalBytes = 0;
    let scannedCommands = 0;
    const observations: DetectedViolation[] = [];

    const consume = (chunk: Buffer, target: "stdout" | "stderr") => {
      totalBytes += chunk.byteLength;
      if (totalBytes > this.config.codexMaxOutputBytes) {
        active.outputExceeded = true;
        this.terminate(active);
        return;
      }
      if (target === "stdout") {
        stdout += chunk.toString("utf8");
        const lines = stdout.split(/\r?\n/);
        stdout = lines.pop() ?? "";
        for (const line of lines) {
          parseCodexEventLine(line, parsed);
        }
        applyPolicy();
      } else {
        stderr += chunk.toString("utf8");
        if (stderr.length > 16_384) {
          stderr = stderr.slice(-16_384);
        }
      }
    };

    // Scans commands not yet evaluated, records every denial, and arms the
    // kill on the first. Declared here so the final stdout flush (below) is
    // evaluated too — a command in the last unterminated line must not escape.
    const applyPolicy = () => {
      const violations = scanCommands(parsed.commands, scannedCommands, policyContext);
      scannedCommands = parsed.commands.length;
      // Step budget is a hard resource limit: enforced regardless of monitor
      // mode, because a runaway loop must be stopped whether or not command
      // policy is in shadow mode.
      if (!active.budgetExceeded && parsed.commands.length > this.config.policyMaxCommands) {
        active.budgetExceeded = true;
        this.terminate(active);
      }
      for (const violation of violations) observations.push(violation);
      if (violations.length > 0 && !active.violation) {
        active.violation = violations[0]!;
        if (this.config.policyEnforcement === "enforce") this.terminate(active);
      }
    };

    child.stdout.on("data", (chunk: Buffer) => consume(chunk, "stdout"));
    child.stderr.on("data", (chunk: Buffer) => consume(chunk, "stderr"));

    const timeout = setTimeout(() => {
      active.timedOut = true;
      this.terminate(active);
    }, this.config.codexTimeoutMs);
    timeout.unref();

    try {
      const exitCode = await new Promise<number>((resolve, reject) => {
        child.once("error", reject);
        child.once("close", (code) => resolve(code ?? 1));
      });
      if (stdout.trim()) {
        parseCodexEventLine(stdout.trim(), parsed);
      }
      // The final flush may have added commands; evaluate them before deciding.
      applyPolicy();
      if (active.cancelled) {
        throw new RunCancelledError();
      }
      if (active.violation && this.config.policyEnforcement === "enforce") {
        throw new PolicyViolationError(
          active.violation.rule,
          active.violation.command,
          active.violation.detail,
          active.violation.hosts ?? [],
        );
      }
      if (active.budgetExceeded) {
        throw new BudgetExceededError(
          this.config.policyMaxCommands,
          parsed.commands.length,
        );
      }
      if (active.timedOut) {
        throw new Error("Codex timed out after " + this.config.codexTimeoutMs + " ms");
      }
      if (active.outputExceeded) {
        throw new Error("Codex output exceeded CODEX_MAX_OUTPUT_BYTES");
      }
      if (exitCode !== 0) {
        const detail = parsed.errors.at(-1) ?? stderr.trim() ?? "No error detail";
        throw new Error("Codex exited with code " + exitCode + ": " + detail);
      }
      const output = parsed.messages.at(-1)?.trim();
      if (!output) {
        throw new Error("Codex completed without an agent message");
      }
      return {
        output,
        threadId: parsed.threadId,
        usage: parsed.usage,
        violations: observations,
      };
    } catch (error) {
      // Carry monitor-mode observations out on the failure path too, so a
      // near-miss is not lost when the run later times out, exceeds budget, or
      // errors. AgentService reads these in monitor mode.
      (error as { observations?: DetectedViolation[] }).observations = observations;
      throw error;
    } finally {
      clearTimeout(timeout);
      if (active.forceKillTimer) clearTimeout(active.forceKillTimer);
      this.active.delete(request.agentId);
    }
  }

  private terminate(active: {
    child: ChildProcess;
    forceKillTimer: NodeJS.Timeout | null;
  }): void {
    if (active.child.exitCode !== null || active.child.signalCode !== null) return;
    active.child.kill("SIGTERM");
    if (!active.forceKillTimer) {
      active.forceKillTimer = setTimeout(() => active.child.kill("SIGKILL"), 3_000);
      active.forceKillTimer.unref();
    }
  }

  private childEnvironment(): NodeJS.ProcessEnv {
    const inheritedNames = [
      "PATH",
      "HOME",
      "TMPDIR",
      "LANG",
      "LC_ALL",
      "SSL_CERT_FILE",
      "SSL_CERT_DIR",
      "HTTP_PROXY",
      "HTTPS_PROXY",
      "NO_PROXY",
      "NODE_EXTRA_CA_CERTS",
      "TERM",
    ] as const;
    const environment: NodeJS.ProcessEnv = {
      CODEX_HOME: this.config.codexHome,
      ARK_API_KEY: this.config.arkApiKey,
      NO_COLOR: "1",
    };
    for (const name of inheritedNames) {
      if (process.env[name] !== undefined) environment[name] = process.env[name];
    }
    return environment;
  }
}
