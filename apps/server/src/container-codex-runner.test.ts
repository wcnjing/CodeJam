import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import {
  agentBrokerName,
  agentNetworkName,
  buildContainerRunArgs,
  containerName,
} from "./container-codex-runner.js";

describe("Container Codex runner", () => {
  it("builds an isolated Docker/Podman-compatible invocation", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      ARK_API_KEY: "secret-that-must-not-appear-in-argv",
      ARK_MODEL: "ep-test",
      CODEX_HOME: "/tmp/codex-home",
      RUNTIME_PROVIDER: "container",
      CONTAINER_ENGINE: "podman",
      CONTAINER_RUNTIME_IMAGE: "runtime:test",
      CONTAINER_USER: "501:20",
      RUNTIME_INSTANCE_ID: "test-instance",
    });
    const args = buildContainerRunArgs(
      {
        agentId: "agent/unsafe",
        workspacePath: "/tmp/agent-workspace",
        prompt: "write a small program",
        threadId: null,
      },
      config,
    );

    expect(containerName("agent/unsafe", "test-instance")).toBe(
      "sentinel-test-instance-agent-unsafe",
    );
    expect(args).toContain("runtime:test");
    expect(args).toContain("type=bind,src=/tmp/agent-workspace,dst=/workspace");
    expect(args).toContain("type=bind,src=/tmp/codex-home,dst=/codex-home");
    expect(args).toContain("501:20");
    expect(args).toContain("workspace-write");
    expect(args).toContain("/workspace");
    expect(args).toContain("io.codejam.instance-id=test-instance");
    expect(args).toContain("keep-id");
    expect(args).not.toContain("secret-that-must-not-appear-in-argv");
  });

  it("resumes a thread inside the mounted Runtime workspace", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      CODEX_HOME: "/tmp/codex-home",
      RUNTIME_PROVIDER: "container",
    });
    const args = buildContainerRunArgs(
      {
        agentId: "agent",
        workspacePath: "/tmp/workspace",
        prompt: "continue",
        threadId: "thread-123",
      },
      config,
    );
    expect(args.slice(-3)).toEqual(["resume", "thread-123", "continue"]);
    expect(args).not.toContain("keep-id");
  });
});

const baseEnv = {
  NODE_ENV: "test",
  ARK_API_KEY: "secret-that-must-not-appear-in-argv",
  ARK_MODEL: "ep-test",
  CODEX_HOME: "/tmp/codex-home",
  RUNTIME_PROVIDER: "container",
  CONTAINER_RUNTIME_IMAGE: "runtime:test",
  RUNTIME_INSTANCE_ID: "test-instance",
} as const;

const request = {
  agentId: "agent-1",
  workspacePath: "/tmp/workspace",
  prompt: "go",
  threadId: null,
};

/** The value following `flag` in an argv pair list. */
const valueAfter = (args: string[], flag: string) => args[args.indexOf(flag) + 1];

describe("container hardening controls", () => {
  it("mounts a read-only root with a noexec tmpfs by default", () => {
    const args = buildContainerRunArgs(request, loadConfig({ ...baseEnv }));
    expect(args).toContain("--read-only");
    expect(valueAfter(args, "--tmpfs")).toBe("/tmp:rw,nodev,nosuid,noexec,size=64m");
  });

  it("leaves the workspace and CODEX_HOME writable under a read-only root", () => {
    // Bind mounts are not part of the container root filesystem, so --read-only
    // must not cost the Agent its own workspace. If this ever regresses, the
    // Agent cannot work at all.
    const args = buildContainerRunArgs(request, loadConfig({ ...baseEnv }));
    expect(args).toContain("type=bind,src=/tmp/workspace,dst=/workspace");
    expect(args).toContain("type=bind,src=/tmp/codex-home,dst=/codex-home");
  });

  it("can lift the read-only root deliberately", () => {
    const args = buildContainerRunArgs(
      request,
      loadConfig({ ...baseEnv, CONTAINER_READ_ONLY_ROOT: "false" }),
    );
    expect(args).not.toContain("--read-only");
    expect(args).not.toContain("--tmpfs");
  });

  it("falls back to the bridge network when isolation is turned off", () => {
    // Opting out is a deliberate act and has to still produce a working Agent.
    const args = buildContainerRunArgs(
      request,
      loadConfig({ ...baseEnv, CONTAINER_EGRESS_ISOLATION: "false" }),
    );
    expect(valueAfter(args, "--network")).toBe("bridge");
    expect(args.join(" ")).not.toContain("HTTPS_PROXY");
  });

  it("joins a per-run isolated network and points at the broker by default", () => {
    const config = loadConfig({ ...baseEnv });
    const args = buildContainerRunArgs(request, config);
    expect(valueAfter(args, "--network")).toBe("sentinel-test-instance-agent-1-net");
    expect(agentNetworkName("agent-1", config)).toBe("sentinel-test-instance-agent-1-net");
    // Per-run, not a shared broker: one compromised Agent must not be able to
    // reach — or exhaust — the broker another Agent's run depends on.
    expect(args).toContain("HTTPS_PROXY=http://sentinel-test-instance-agent-1-broker:8080");
    expect(args).toContain("HTTP_PROXY=http://sentinel-test-instance-agent-1-broker:8080");
    // An empty NO_PROXY matters: a default bypass list would let the Agent
    // reach anything it could name as "local" without going through the broker.
    expect(args).toContain("NO_PROXY=");
  });

  it("never puts the API key value in argv", () => {
    const args = buildContainerRunArgs(request, loadConfig({ ...baseEnv }));
    expect(args.join(" ")).not.toContain("secret-that-must-not-appear-in-argv");
  });

  // Regression: the first live end-to-end run under the default egress
  // isolation failed with a transport error against the Ark URL. The cause was
  // not the network — it was this name. `sentinel-local-501-3099439417-` plus a
  // UUID plus `-broker` is 73 characters, a DNS label may be 63, so the Agent
  // resolved nothing for its HTTPS_PROXY host and had no route to the model.
  // Nothing in the unit tests or in verify:egress used a production-shaped
  // name, so every check was green.
  it("keeps the broker and network names inside the 63-octet DNS label limit", () => {
    const config = loadConfig({
      ...baseEnv,
      RUNTIME_INSTANCE_ID: "local-501-3099439417",
    });
    const agentId = "d8da4472-7657-4c04-a087-ea659fc6f4f3";

    const broker = agentBrokerName(agentId, config);
    const network = agentNetworkName(agentId, config);

    expect(broker.length).toBeLessThanOrEqual(63);
    expect(network.length).toBeLessThanOrEqual(63);
    // A dot would split the label and a `_` is not a legal hostname character,
    // so the name has to be narrower than what the engine would accept.
    expect(broker).toMatch(/^[a-zA-Z0-9][a-zA-Z0-9-]*$/);
    // The Agent must be pointed at the same name the broker is created with.
    expect(buildContainerRunArgs({ ...request, agentId }, config)).toContain(
      "HTTPS_PROXY=http://" + broker + ":8080",
    );
  });

  it("keeps truncated names deterministic and distinct per agent", () => {
    const config = loadConfig({
      ...baseEnv,
      RUNTIME_INSTANCE_ID: "an-instance-id-long-enough-to-tr",
    });
    const first = "0000000000000000000000000000000-aaaa";
    const second = "0000000000000000000000000000000-bbbb";

    // Deterministic, or stale-topology cleanup cannot find what to remove.
    expect(agentBrokerName(first, config)).toBe(agentBrokerName(first, config));
    // Distinct, or two agents sharing a prefix share a broker.
    expect(agentBrokerName(first, config)).not.toBe(agentBrokerName(second, config));
    expect(agentBrokerName(first, config).length).toBeLessThanOrEqual(63);
  });
});
