import type { AppConfig } from "../core/config.js";
import { ContainerCodexRunner } from "./container-codex-runner.js";
import { CodexRunner } from "./codex-runner.js";
import type { AgentRunner } from "../core/types.js";

export function createRunner(config: AppConfig): AgentRunner {
  return config.runtimeProvider === "container"
    ? new ContainerCodexRunner(config)
    : new CodexRunner(config);
}
