import { mkdir } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import { REVIEWABLE_RULES } from "./command-policy.js";
import { PrincipalRegistry } from "./principals.js";
import { safeWriteFile } from "./safe-write.js";

const envSchema = z.object({
  HOST: z.string().default("0.0.0.0"),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  LOG_LEVEL: z.string().default("info"),
  APP_DATA_DIR: z.string().default(path.resolve(".data")),
  AGENT_WORKSPACE_ROOT: z.string().default(path.resolve("workspaces")),
  CODEX_HOME: z.string().default(path.resolve("codex-home")),
  CODEX_BIN: z.string().default("codex"),
  CODEX_SANDBOX_MODE: z
    .enum(["read-only", "workspace-write", "danger-full-access"])
    .default("workspace-write"),
  CODEX_TIMEOUT_MS: z.coerce.number().int().min(1_000).default(600_000),
  CODEX_MAX_OUTPUT_BYTES: z.coerce.number().int().min(65_536).default(2_097_152),
  // `replay` is a demo/CI provider: recorded model output, real everything else.
  RUNTIME_PROVIDER: z.enum(["local-process", "container", "replay"]).default("local-process"),
  CONTAINER_ENGINE: z.string().min(1).default("docker"),
  CONTAINER_RUNTIME_IMAGE: z.string().min(1).default("volc-agent-runtime:local"),
  CONTAINER_CPU_LIMIT: z.coerce.number().positive().default(2),
  CONTAINER_MEMORY_LIMIT: z
    .string()
    .regex(/^\d+(?:\.\d+)?[bkmg]$/i)
    .default("2g"),
  CONTAINER_PIDS_LIMIT: z.coerce.number().int().positive().default(256),
  CONTAINER_USER: z.string().optional(),
  // Defence in depth for the runtime container. Both default on; they exist as
  // switches because a runtime image that writes outside its bind mounts needs
  // the read-only root lifted to run at all, and that should be a deliberate act.
  CONTAINER_READ_ONLY_ROOT: z
    .enum(["true", "false"])
    .default("true")
    .transform((value) => value === "true"),
  // On by default: the container runtime is already opt-in, so anyone reaching
  // this path wants the hardened one. It needs the broker image — build it with
  // `npm run build:broker` — and fails loudly rather than quietly downgrading if
  // it is missing. Verified end to end by `npm run verify:egress`.
  CONTAINER_EGRESS_ISOLATION: z
    .enum(["true", "false"])
    .default("true")
    .transform((value) => value === "true"),
  CONTAINER_EGRESS_BROKER_IMAGE: z.string().min(1).default("volc-egress-broker:local"),
  CONTAINER_EGRESS_BROKER_PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  // The network the broker gets its second, outbound-capable home on. The Agent
  // is never attached to this one.
  CONTAINER_EGRESS_OUTBOUND_NETWORK: z.string().min(1).default("bridge"),
  CONTAINER_EGRESS_READY_TIMEOUT_MS: z.coerce.number().int().positive().default(15_000),
  RUNTIME_INSTANCE_ID: z
    .string()
    .trim()
    .min(1)
    .max(48)
    .regex(/^[a-zA-Z0-9_.-]+$/)
    .default("default"),
  // Named approver credentials: comma-separated id:token pairs. The id is what
  // an approval records, so it must come from here and never from a request body.
  APP_PRINCIPALS: z.string().default(""),
  ARK_API_KEY: z.string().optional(),
  ARK_MODEL: z.string().optional(),
  ARK_BASE_URL: z
    .string()
    .url()
    .default("https://ark.cn-beijing.volces.com/api/v3"),
  POLICY_ALLOWED_HOSTS: z.string().default(""),
  POLICY_ENFORCEMENT: z.enum(["enforce", "monitor"]).default("enforce"),
  // Rules whose denials pause for human approval instead of hard-blocking.
  // Deliberately defaults to egress only: secret-access rules are never
  // reviewable, so no human can approve exfiltrating a protected secret.
  POLICY_REVIEW_RULES: z
    .string()
    .default(
      "network-egress-denied,network-egress-denied-implicit,file-write-unresolved-target",
    ),
  // Step budget: max shell commands one run may execute before it is killed as
  // runaway. Enforced by the platform, not the agent, and always on.
  POLICY_MAX_COMMANDS: z.coerce.number().int().positive().default(50),
  // How long policyEvents/approvals survive in the store (TM-OPS-001). A
  // pending approval is exempt regardless of age; only resolved history ages out.
  AUDIT_RETENTION_DAYS: z.coerce.number().int().positive().default(90),
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
});

export type AppConfig = ReturnType<typeof loadConfig>;

export function loadConfig(environment: NodeJS.ProcessEnv = process.env) {
  if ((environment.APP_AUTH_TOKEN ?? "").trim().length > 0) {
    throw new Error(
      "APP_AUTH_TOKEN has been replaced by APP_PRINCIPALS. A shared token cannot be " +
        "attributed to a person, so approvals no longer accept one. Set " +
        'APP_PRINCIPALS="alice:<token>,bob:<token>" and remove APP_AUTH_TOKEN.',
    );
  }
  const env = envSchema.parse(environment);
  const loopbackHosts = new Set(["127.0.0.1", "::1", "localhost"]);
  const remoteProduction = env.NODE_ENV === "production" && !loopbackHosts.has(env.HOST);
  const principals = PrincipalRegistry.parse(env.APP_PRINCIPALS, {
    minTokenLength: remoteProduction ? 24 : 8,
  });
  if (remoteProduction && principals.size === 0) {
    throw new Error(
      "APP_PRINCIPALS must configure at least one principal for a non-loopback production server",
    );
  }
  const defaultContainerUser =
    typeof process.getuid === "function" && typeof process.getgid === "function"
      ? process.getuid() + ":" + process.getgid()
      : "1000:1000";
  return {
    host: env.HOST,
    port: env.PORT,
    logLevel: env.LOG_LEVEL,
    dataDirectory: path.resolve(env.APP_DATA_DIR),
    workspaceRoot: path.resolve(env.AGENT_WORKSPACE_ROOT),
    codexHome: path.resolve(env.CODEX_HOME),
    codexBin: env.CODEX_BIN,
    codexSandboxMode: env.CODEX_SANDBOX_MODE,
    codexTimeoutMs: env.CODEX_TIMEOUT_MS,
    codexMaxOutputBytes: env.CODEX_MAX_OUTPUT_BYTES,
    runtimeProvider: env.RUNTIME_PROVIDER,
    containerEngine: env.CONTAINER_ENGINE,
    containerRuntimeImage: env.CONTAINER_RUNTIME_IMAGE,
    containerCpuLimit: env.CONTAINER_CPU_LIMIT,
    containerMemoryLimit: env.CONTAINER_MEMORY_LIMIT,
    containerPidsLimit: env.CONTAINER_PIDS_LIMIT,
    containerUser: env.CONTAINER_USER?.trim() || defaultContainerUser,
    containerReadOnlyRoot: env.CONTAINER_READ_ONLY_ROOT,
    containerEgressIsolation: env.CONTAINER_EGRESS_ISOLATION,
    containerEgressBrokerImage: env.CONTAINER_EGRESS_BROKER_IMAGE,
    containerEgressBrokerPort: env.CONTAINER_EGRESS_BROKER_PORT,
    containerEgressOutboundNetwork: env.CONTAINER_EGRESS_OUTBOUND_NETWORK,
    containerEgressReadyTimeoutMs: env.CONTAINER_EGRESS_READY_TIMEOUT_MS,
    runtimeInstanceId: env.RUNTIME_INSTANCE_ID,
    principals,
    arkApiKey: env.ARK_API_KEY?.trim() ?? "",
    arkModel: env.ARK_MODEL?.trim() ?? "",
    arkBaseUrl: env.ARK_BASE_URL.replace(/\/+$/, ""),
    policyAllowedHosts: env.POLICY_ALLOWED_HOSTS.split(",")
      .map((host) => host.trim().toLowerCase())
      .filter((host) => host.length > 0),
    policyEnforcement: env.POLICY_ENFORCEMENT,
    policyMaxCommands: env.POLICY_MAX_COMMANDS,
    policyReviewRules: parseReviewRules(env.POLICY_REVIEW_RULES),
    auditRetentionDays: env.AUDIT_RETENTION_DAYS,
    nodeEnv: env.NODE_ENV,
  };
}

/**
 * Parses POLICY_REVIEW_RULES and enforces the code-level invariant that only
 * REVIEWABLE_RULES may be human-approved. A config that names a secret-access
 * rule is rejected at startup — loudly — rather than silently letting an
 * operator approve exfiltration. Fails closed: unknown rules are refused.
 */
function parseReviewRules(raw: string): string[] {
  const requested = raw
    .split(",")
    .map((rule) => rule.trim())
    .filter((rule) => rule.length > 0);
  const forbidden = requested.filter((rule) => !REVIEWABLE_RULES.includes(rule));
  if (forbidden.length > 0) {
    throw new Error(
      "POLICY_REVIEW_RULES may only contain reviewable rules (" +
        REVIEWABLE_RULES.join(", ") +
        "). Secret-access rules can never be human-approved. Rejected: " +
        forbidden.join(", "),
    );
  }
  return requested;
}

export function isArkConfigured(config: AppConfig): boolean {
  return (
    config.arkApiKey.length > 0 &&
    !config.arkApiKey.startsWith("replace-") &&
    config.arkModel.length > 0 &&
    !config.arkModel.includes("replace-")
  );
}

export function codexConfigToml(config: AppConfig): string {
  return [
    "# Generated by Volc Agent Launchpad. Edit environment variables, not this file.",
    "model = " + JSON.stringify(config.arkModel || "ep-not-configured"),
    'model_provider = "volcengine_ark"',
    "",
    "[model_providers.volcengine_ark]",
    'name = "Volcengine Ark"',
    "base_url = " + JSON.stringify(config.arkBaseUrl),
    'env_key = "ARK_API_KEY"',
    'wire_api = "responses"',
    "requires_openai_auth = false",
    "",
    // Codex itself needs ARK_API_KEY for model requests, but Agent-authored shell
    // commands must not inherit it. This is the credential boundary; command
    // text matching below is only defense in depth. Official Codex config:
    // https://developers.openai.com/codex/config-file/config-reference
    "[shell_environment_policy]",
    'inherit = "all"',
    // Keep Codex's automatic KEY/SECRET/TOKEN exclusions as well as the exact
    // Ark rule below, so generic environment inspection cannot reveal adjacent
    // credentials either.
    "ignore_default_excludes = false",
    // `exclude` is the documented key for dropping variables; it takes a list of
    // patterns on [shell_environment_policy] itself. There is no `filters`
    // sub-table, so naming one left the explicit rule inert and the boundary
    // resting entirely on the default KEY/SECRET/TOKEN patterns.
    'exclude = ["ARK_API_KEY"]',
    "",
  ].join("\n");
}

/**
 * CODEX_HOME is Agent-controlled ground, exactly like the workspace: the
 * container runner bind-mounts it writable into the Agent container, and the
 * host rewrites config.toml on every server start. A plain `writeFile` here is
 * the same hole safe-write.ts closes for the workspace — the Agent replaces
 * config.toml with a link to the audit store and the next start writes through
 * it — so this write goes through the same door. See TM-AGENT-008.
 */
export async function writeCodexConfig(config: AppConfig): Promise<void> {
  await mkdir(config.codexHome, { recursive: true });
  const toml = codexConfigToml(config);
  await safeWriteFile(config.codexHome, path.join(config.codexHome, "config.toml"), toml, {
    mode: 0o600,
  });
}
