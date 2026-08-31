import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import {
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

  it("points the isolated Agent's DNS at the broker's address", () => {
    // The --internal network has no outbound DNS at all; the broker's DNS
    // forwarder is the only resolver the Agent can reach, so --dns must name
    // the broker's address on the isolated network.
    const config = loadConfig({ ...baseEnv, CONTAINER_EGRESS_ISOLATION: "true" });
    const args = buildContainerRunArgs(request, config, "172.30.0.9");
    expect(args).toContain("--dns");
    expect(valueAfter(args, "--dns")).toBe("172.30.0.9");
    // External resolvers are unreachable on the isolated network, so
    // CONTAINER_DNS must NOT be passed to the Agent there.
    expect(args).not.toContain("8.8.8.8");
  });

  it("emits no --dns flags for an isolated run without a broker address", () => {
    const args = buildContainerRunArgs(request, loadConfig({ ...baseEnv }));
    expect(args).not.toContain("--dns");
  });

  it("passes explicit resolvers to the Agent in bridge mode when CONTAINER_DNS is set", () => {
    const config = loadConfig({
      ...baseEnv,
      CONTAINER_EGRESS_ISOLATION: "false",
      CONTAINER_DNS: "1.1.1.1, 8.8.8.8",
    });
    const args = buildContainerRunArgs(request, config);
    expect(args).toContain("--dns");
    expect(valueAfter(args, "--dns")).toBe("1.1.1.1");
    expect(args).toContain("8.8.8.8");
  });

  it("never puts the API key value in argv", () => {
    const args = buildContainerRunArgs(request, loadConfig({ ...baseEnv }));
    expect(args.join(" ")).not.toContain("secret-that-must-not-appear-in-argv");
  });
});
