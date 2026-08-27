import path from "node:path";
import { AgentService } from "./core/agent-service.js";
import { createApp } from "./core/app.js";
import { loadConfig, writeCodexConfig } from "./core/config.js";
import { createRunner } from "./runners/runner-factory.js";
import { JsonStore } from "./core/store.js";
import { WorkspaceManager } from "./core/workspace.js";

const config = loadConfig();
await writeCodexConfig(config);

const store = new JsonStore(path.join(config.dataDirectory, "launchpad.json"));
const workspaces = new WorkspaceManager(config.workspaceRoot);
const runner = createRunner(config);
const service = new AgentService(config, store, workspaces, runner);
await service.initialize();

const app = await createApp(config, service);

const shutdown = async (signal: string) => {
  app.log.info({ signal }, "Shutting down");
  await app.close();
  process.exit(0);
};

process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));

await app.listen({ host: config.host, port: config.port });
