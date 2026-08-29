import type { AppConfig } from "./config.js";
import { ContainerCodexRunner } from "./container-codex-runner.js";
import { CodexRunner } from "./codex-runner.js";
import { ReplayRunner } from "./replay-runner.js";
import type { AgentRunner } from "./types.js";

export function createRunner(config: AppConfig): AgentRunner {
  // `replay` streams a recorded Codex event stream through the real policy
  // engine, audit trail and approval loop, faking only the model. It exists so
  // the governance loop can be demonstrated without a key, a container engine or
  // a network - see replay-runner.ts for exactly which parts are real.
  if (config.runtimeProvider === "replay") {
    return new ReplayRunner(config);
  }
  return config.runtimeProvider === "container"
    ? new ContainerCodexRunner(config)
    : new CodexRunner(config);
}
