#!/usr/bin/env node
/**
 * Live egress containment check — `npm run verify:egress`.
 *
 * Stands up the real topology against a real container engine and proves the
 * containment claim by observation rather than by argv inspection: an Agent on
 * the isolated network reaches the allowlisted endpoint and nothing else, and
 * has no route at all when it does not go through the broker.
 *
 * This exists because the unit tests cannot prove it. They assert the arguments
 * we pass to the engine; only the engine can tell us whether `--internal`
 * really installs no route, whether the broker is reachable by name over the
 * embedded DNS, and whether a proxied client actually gets through. Those are
 * the claims the README makes, so they get checked against the engine.
 *
 *   npm run verify:egress                  # uses example.com as the allowlist
 *   ALLOW_URL=https://ark.example.com npm run verify:egress
 *
 * Exits non-zero on any failed check. Cleans up its own network and containers
 * on every path, including Ctrl-C.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const ENGINE = process.env.CONTAINER_ENGINE || "docker";
const BROKER_IMAGE = process.env.BROKER_IMAGE || "volc-egress-broker:local";
// A public endpoint the check can actually reach. The point is the allow/deny
// boundary, not this particular host.
const ALLOW_URL = process.env.ALLOW_URL || "https://example.com";
const ALLOW_HOST = new URL(ALLOW_URL).hostname;
const DENY_HOST = process.env.DENY_HOST || "github.com";
const CLIENT_IMAGE = "curlimages/curl:latest";

const suffix = Math.random().toString(36).slice(2, 8);
const NET = `verify-egress-${suffix}`;
const BROKER = `verify-egress-broker-${suffix}`;

let failures = 0;
const results = [];

function record(ok, name, detail) {
  results.push({ ok, name, detail });
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name.padEnd(46)} ${detail}`);
}

async function engine(args, options = {}) {
  try {
    const { stdout, stderr } = await execFileAsync(ENGINE, args, { timeout: 90_000, ...options });
    return { code: 0, stdout, stderr };
  } catch (error) {
    return { code: error.code ?? 1, stdout: error.stdout ?? "", stderr: error.stderr ?? String(error) };
  }
}

/** Runs curl inside a container on the isolated network and returns its code. */
async function curlFrom(url, { viaProxy }) {
  const proxyEnv = viaProxy
    ? ["-e", `HTTPS_PROXY=http://${BROKER}:8080`, "-e", `HTTP_PROXY=http://${BROKER}:8080`, "-e", "NO_PROXY="]
    : [];
  const { stdout } = await engine([
    "run", "--rm", "--network", NET, ...proxyEnv,
    "--entrypoint", "curl", CLIENT_IMAGE,
    "-sS", "--max-time", "15", "-o", "/dev/null", "-w", "%{http_code}", url,
  ]);
  return stdout.trim().split("\n").pop() ?? "000";
}

async function cleanup() {
  await engine(["stop", "--timeout", "5", BROKER]);
  await engine(["rm", "--force", BROKER]);
  await engine(["network", "rm", NET]);
}

process.on("SIGINT", async () => { await cleanup(); process.exit(130); });

console.log("");
console.log("Live egress containment check");
console.log("-".repeat(74));
console.log(`  engine ${ENGINE}   allow ${ALLOW_HOST}   deny ${DENY_HOST}`);
console.log("-".repeat(74));

try {
  const version = await engine(["version", "--format", "{{.Server.Version}}"]);
  if (version.code !== 0) {
    console.log(`  SKIP  no reachable ${ENGINE} daemon; this check needs one.`);
    process.exit(0);
  }
  record(true, "Container engine reachable", `${ENGINE} ${version.stdout.trim()}`);

  const image = await engine(["image", "inspect", BROKER_IMAGE]);
  if (image.code !== 0) {
    record(false, "Broker image present", `${BROKER_IMAGE} missing — run npm run build:broker`);
    throw new Error("missing broker image");
  }
  record(true, "Broker image present", BROKER_IMAGE);

  await cleanup();

  const created = await engine(["network", "create", "--internal", NET]);
  record(created.code === 0, "Isolated network created", created.code === 0 ? NET : created.stderr.trim());

  const started = await engine([
    "run", "--detach", "--rm", "--name", BROKER, "--network", NET,
    "--security-opt", "no-new-privileges", "--cap-drop", "ALL", "--read-only",
    "-e", `EGRESS_ALLOW_URL=${ALLOW_URL}`, BROKER_IMAGE,
  ]);
  record(started.code === 0, "Broker sidecar started", started.code === 0 ? BROKER : started.stderr.trim());

  const connected = await engine(["network", "connect", "bridge", BROKER]);
  record(connected.code === 0, "Broker dual-homed to an outbound network", connected.code === 0 ? "bridge" : connected.stderr.trim());

  // The broker binds in milliseconds, but give it a moment before the clients.
  await new Promise((r) => setTimeout(r, 1500));
  const logs = await engine(["logs", BROKER]);
  record(
    logs.stdout.includes("egress-broker-ready") || logs.stderr.includes("egress-broker-ready"),
    "Broker reports ready",
    `allowlisting ${ALLOW_HOST}`,
  );

  // --- the three claims -----------------------------------------------------
  const allowed = await curlFrom(ALLOW_URL, { viaProxy: true });
  record(allowed === "200", "Allowlisted endpoint reachable via broker", `HTTP ${allowed}`);

  const denied = await curlFrom(`https://${DENY_HOST}`, { viaProxy: true });
  record(denied === "000", "Non-allowlisted endpoint refused by broker", `curl exit code ${denied}`);

  const metadata = await curlFrom("http://169.254.169.254/latest/meta-data/", { viaProxy: true });
  record(metadata === "000", "Cloud metadata unreachable", `curl exit code ${metadata}`);

  // The one that makes the others mean something: without the proxy there is no
  // route at all, so the broker is not merely the convenient path but the only
  // one. If this ever returns 200, the network is not actually isolated and
  // every check above is measuring the proxy rather than the containment.
  const direct = await curlFrom(ALLOW_URL, { viaProxy: false });
  record(direct === "000", "No route without the broker", `curl exit code ${direct}`);

  const denials = (logs.stderr + (await engine(["logs", BROKER])).stderr)
    .split("\n").filter((line) => line.includes("egress-denied")).length;
  record(denials > 0, "Denials recorded in the broker log", `${denials} logged`);
} catch (error) {
  if (!String(error.message).includes("missing broker image")) {
    console.log(`  FAIL  unexpected error: ${error.message}`);
    failures += 1;
  }
} finally {
  await cleanup();
}

console.log("-".repeat(74));
console.log(failures === 0
  ? `  CONTAINED: ${results.length} checks passed against a real engine.`
  : `  NOT CONTAINED: ${failures} of ${results.length} checks failed.`);
console.log("");
process.exit(failures === 0 ? 0 : 1);
