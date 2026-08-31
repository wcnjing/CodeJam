import { afterEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

/**
 * The preflight check that costs money is the one worth testing.
 *
 * `GET /models` answers 200 for an account whose model has been paused on a
 * spend limit, so preflight used to report "credentials accepted" and every Run
 * then failed several minutes later, after a full image build. The inference
 * probe exists to catch that, and its most important branch — the paused model —
 * is the one branch a live account cannot be made to produce on demand. So it is
 * produced here instead, by an Ark stand-in that returns the real error envelope.
 */

const execFileAsync = promisify(execFile);
const script = fileURLToPath(new URL("../../../scripts/preflight.mjs", import.meta.url));
// Preflight probes three ports and the container engine before it gets to the
// model call, so it is seconds slow by design.
const TIMEOUT = 60_000;
const servers: Server[] = [];

interface PreflightResult {
  status: "pass" | "warn" | "fail" | "skip";
  name: string;
  detail: string;
  hint: string | null;
}

/** An Ark stand-in: reachable and credentialled, with a scripted /responses. */
async function arkStub(responses: { status: number; body: unknown }): Promise<string> {
  const server = createServer((request, response) => {
    if (request.url?.endsWith("/models")) {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ data: [] }));
      return;
    }
    response.writeHead(responses.status, { "content-type": "application/json" });
    response.end(JSON.stringify(responses.body));
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (typeof address === "string" || address === null) throw new Error("no port");
  return `http://127.0.0.1:${address.port}/api/v3`;
}

/**
 * Async on purpose. `spawnSync` blocks this process's event loop, so the stub
 * server below never gets to answer and every probe hangs to its own timeout.
 */
async function runPreflight(
  env: Record<string, string>,
  extraArgs: string[] = [],
): Promise<PreflightResult[]> {
  // Preflight exits non-zero on any hard failure, which several of these cases
  // are, so a rejection carries the stdout we want rather than an error.
  const done = await execFileAsync(process.execPath, [script, "--json", ...extraArgs], {
    env: { ...process.env, ...env },
  }).catch((error: { stdout?: string }) => ({ stdout: error.stdout ?? "" }));
  return (JSON.parse(done.stdout) as { results: PreflightResult[] }).results;
}

const inference = (results: PreflightResult[]) =>
  results.find((entry) => entry.name === "Ark inference");

afterEach(async () => {
  for (const server of servers.splice(0)) {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

describe("preflight inference probe", () => {
  it("fails on a model paused by a spend limit, and names the console fix", async () => {
    const base = await arkStub({
      status: 429,
      body: {
        error: {
          code: "SetLimitExceeded",
          message:
            "Your account [3004222323] has reached the set inference limit for the " +
            "[deepseek-v4-pro-ga] model, and the model service has been paused. To " +
            'continue using this model, please visit the Model Activation page to ' +
            'adjust or close the "Safe Experience Mode".',
          type: "TooManyRequests",
        },
      },
    });

    const results = await runPreflight({
      ARK_BASE_URL: base,
      ARK_API_KEY: "test-key",
      ARK_MODEL: "deepseek-v4-pro-ga-260813",
    });

    // Reachability still passes — that is the whole point of the new check.
    expect(results.find((entry) => entry.name === "ARK_BASE_URL")?.status).toBe("pass");

    const probe = inference(results);
    expect(probe?.status).toBe("fail");
    expect(probe?.detail).toContain("PAUSED");
    // A hint that does not say where to go leaves the reader retrying forever.
    expect(probe?.hint).toContain("Model Activation");
    expect(probe?.hint).toContain("Safe Experience Mode");
  }, TIMEOUT);

  it("treats an ordinary 429 as transient rather than as a paused model", async () => {
    const base = await arkStub({
      status: 429,
      body: { error: { code: "RateLimitExceeded", message: "too many requests", type: "TooManyRequests" } },
    });

    const probe = inference(
      await runPreflight({ ARK_BASE_URL: base, ARK_API_KEY: "test-key", ARK_MODEL: "ep-test" }),
    );
    expect(probe?.status).toBe("warn");
    expect(probe?.hint).toContain("transient");
  }, TIMEOUT);

  it("passes when the model answers, including a max_output_tokens truncation", async () => {
    // A reasoning model spends the 16-token budget on reasoning and comes back
    // incomplete. Reaching the model is the signal; what it said is not.
    const base = await arkStub({
      status: 200,
      body: { status: "incomplete", incomplete_details: { reason: "length" }, output: [] },
    });

    const probe = inference(
      await runPreflight({ ARK_BASE_URL: base, ARK_API_KEY: "test-key", ARK_MODEL: "ep-test" }),
    );
    expect(probe?.status).toBe("pass");
    expect(probe?.detail).toContain("incomplete");
  }, TIMEOUT);

  it("does not bill for a probe when the endpoint is already failing", async () => {
    const base = await arkStub({ status: 200, body: {} });

    // A rejected key fails reachability; a second call would only cost money.
    const server = servers[0];
    server.removeAllListeners("request");
    server.on("request", (_request, response) => {
      response.writeHead(401, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: { code: "AuthenticationError" } }));
    });

    const results = await runPreflight({
      ARK_BASE_URL: base,
      ARK_API_KEY: "test-key",
      ARK_MODEL: "ep-test",
    });
    expect(results.find((entry) => entry.name === "ARK_BASE_URL")?.status).toBe("fail");
    const probe = inference(results);
    expect(probe?.status).toBe("skip");
    expect(probe?.detail).toContain("ARK_BASE_URL failed");
  }, TIMEOUT);

  it("skips the billed call under --no-inference", async () => {
    const base = await arkStub({ status: 200, body: { status: "completed" } });
    const results = await runPreflight(
      { ARK_BASE_URL: base, ARK_API_KEY: "test-key", ARK_MODEL: "ep-test" },
      ["--no-inference"],
    );
    expect(inference(results)?.status).toBe("skip");
    expect(inference(results)?.detail).toContain("--no-inference");
  }, TIMEOUT);
});
