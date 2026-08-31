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
import { createConnection } from "node:net";
import { promisify } from "node:util";
// Imported, not restated: the check must exercise the argv the runner actually
// builds, or it is testing a copy of the production code rather than the code.
import { buildBrokerProbeArgs } from "../apps/server/src/network-isolation.js";

const execFileAsync = promisify(execFile);

const ENGINE = process.env.CONTAINER_ENGINE || "docker";
const BROKER_IMAGE = process.env.BROKER_IMAGE || "volc-egress-broker:local";
// A public endpoint the check can actually reach. The point is the allow/deny
// boundary, not this particular host.
const ALLOW_URL = process.env.ALLOW_URL || "https://example.com";
const ALLOW_HOST = new URL(ALLOW_URL).hostname;
const DENY_HOST = process.env.DENY_HOST || "github.com";
const CLIENT_IMAGE = "curlimages/curl:latest";
const RUNTIME_IMAGE = process.env.CONTAINER_RUNTIME_IMAGE || "volc-agent-runtime:local";

const suffix = Math.random().toString(36).slice(2, 8);
const NET = `verify-egress-${suffix}`;
// Padded to the full 63-octet DNS label. The names the runner generates are
// long — an instance id plus an agent UUID plus `-broker` — and a broker whose
// name is one octet over resolves to nothing, so the Agent has no route to the
// model while every other check stays green. Checking at the boundary here
// means the live run exercises the same length the product does.
const BROKER = `verify-egress-broker-${suffix}`.padEnd(63, "x");
// The approval leg gets its OWN broker, because that is how the product works:
// a grant is an environment variable on a broker container created for one run
// and destroyed with it, never a mutation of a broker already running.
const GRANT_BROKER = `verify-egress-grant-${suffix}`.padEnd(63, "x");

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
async function curlFrom(url, { viaProxy, broker = BROKER }) {
  const proxyEnv = viaProxy
    ? ["-e", `HTTPS_PROXY=http://${broker}:8080`, "-e", `HTTP_PROXY=http://${broker}:8080`, "-e", "NO_PROXY="]
    : [];
  const { stdout } = await engine([
    "run", "--rm", "--network", NET, ...proxyEnv,
    "--entrypoint", "curl", CLIENT_IMAGE,
    "-sS", "--max-time", "15", "-o", "/dev/null", "-w", "%{http_code}", url,
  ]);
  return stdout.trim().split("\n").pop() ?? "000";
}

async function cleanup() {
  for (const broker of [BROKER, GRANT_BROKER]) {
    await engine(["stop", "--timeout", "5", broker]);
    await engine(["rm", "--force", broker]);
  }
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

  // The readiness gate the runner actually uses, run the way the runner runs
  // it. Grepping the log proves the broker said it was listening; this proves
  // something can still connect, which is the claim the gate makes. The probe
  // has to come from the engine — see the host check below for why.
  const probeArgs = buildBrokerProbeArgs(BROKER, 8080);
  let ready = false;
  for (const deadline = Date.now() + 15_000; Date.now() < deadline; ) {
    if ((await engine(probeArgs)).code === 0) {
      ready = true;
      break;
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  record(ready, "Broker readiness probe answers", `via ${ENGINE} exec, allowlisting ${ALLOW_HOST}`);

  const logs = await engine(["logs", BROKER]);
  record(
    logs.stdout.includes("egress-broker-ready") || logs.stderr.includes("egress-broker-ready"),
    "Broker reports ready",
    `allowlisting ${ALLOW_HOST}`,
  );

  // The regression guard for the readiness bug: the broker must NOT be
  // reachable from the host by container name. A probe written that way cannot
  // ever succeed, so it fails every isolated run at the gate — and it does so
  // silently, because unit tests probing 127.0.0.1 pass either way. If this
  // check ever finds the host can connect, the broker has been published and
  // the single edge is no longer single.
  const fromHost = await new Promise((resolve) => {
    const socket = createConnection({ host: BROKER, port: 8080 });
    const settle = (value) => {
      socket.destroy();
      resolve(value);
    };
    socket.once("connect", () => settle(true));
    socket.once("error", () => settle(false));
    socket.setTimeout(3_000, () => settle(false));
  });
  record(fromHost === false, "Broker not reachable from the host", "container name does not resolve");

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

  // --- the granted allowance ------------------------------------------------
  //
  // A human approval adds ONE host to ONE run's broker. Everything above proves
  // the standing allowlist; this proves the granted one, and proves the grant is
  // a property of a container rather than of a running process: it arrives as
  // EGRESS_APPROVED_URLS on a broker started for the granted run and dies with
  // that container.
  const grantStarted = await engine([
    "run", "--detach", "--rm", "--name", GRANT_BROKER, "--network", NET,
    "--security-opt", "no-new-privileges", "--cap-drop", "ALL", "--read-only",
    "-e", `EGRESS_ALLOW_URL=${ALLOW_URL}`,
    "-e", `EGRESS_APPROVED_URLS=https://${DENY_HOST}`, BROKER_IMAGE,
  ]);
  record(
    grantStarted.code === 0,
    "Granted-run broker started",
    grantStarted.code === 0 ? `approving ${DENY_HOST}` : grantStarted.stderr.trim(),
  );
  await engine(["network", "connect", "bridge", GRANT_BROKER]);

  const grantProbe = buildBrokerProbeArgs(GRANT_BROKER, 8080);
  let grantReady = false;
  for (const deadline = Date.now() + 15_000; Date.now() < deadline; ) {
    if ((await engine(grantProbe)).code === 0) {
      grantReady = true;
      break;
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  record(grantReady, "Granted-run broker ready", "for this run only");

  // The host the standing broker refused, reached through the granted one. This
  // is the whole point of an approval: policy and the network now agree.
  const grantedReach = await curlFrom(`https://${DENY_HOST}`, { viaProxy: true, broker: GRANT_BROKER });
  record(grantedReach === "200", "Approved host reachable via granted broker", `HTTP ${grantedReach}`);

  // The grant added a name to the list; it did not empty the list or open it.
  const grantedAllow = await curlFrom(ALLOW_URL, { viaProxy: true, broker: GRANT_BROKER });
  record(grantedAllow === "200", "Standing allowlist survives the grant", `HTTP ${grantedAllow}`);

  const grantedThird = await curlFrom("https://www.wikipedia.org", { viaProxy: true, broker: GRANT_BROKER });
  record(grantedThird === "000", "Grant does not widen to a third host", `curl exit code ${grantedThird}`);

  // Scope: the run that was NOT granted still cannot reach it. Same network,
  // same moment, different broker — which is exactly the per-run boundary the
  // approval is supposed to draw.
  const ungranted = await curlFrom(`https://${DENY_HOST}`, { viaProxy: true });
  record(ungranted === "000", "Grant invisible to the ungranted run", `curl exit code ${ungranted}`);

  // CONTAINER_READ_ONLY_ROOT defaults on, and the PR claims the Agent is
  // unaffected because bind mounts are not part of the container root. That is
  // a claim about a real image, so check it against one when it is present.
  const runtime = await engine(["image", "inspect", RUNTIME_IMAGE]);
  if (runtime.code !== 0) {
    console.log(`  SKIP  read-only root smoke: ${RUNTIME_IMAGE} not built here.`);
  } else {
    const readOnlyArgs = [
      "run", "--rm", "--read-only",
      "--tmpfs", "/tmp:rw,nodev,nosuid,noexec,size=64m",
      "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
      "--mount", `type=bind,src=${process.cwd()},dst=/workspace`,
      "--workdir", "/workspace",
      "--entrypoint", "sh", RUNTIME_IMAGE, "-c",
    ];
    // /tmp is the Agent's scratch and must stay writable; the image root must not.
    const scratch = await engine([...readOnlyArgs, "touch /tmp/probe && echo WRITABLE"]);
    record(
      scratch.stdout.includes("WRITABLE"),
      "Agent scratch still writable read-only",
      scratch.stdout.trim() || scratch.stderr.trim().split("\n")[0],
    );
    const root = await engine([...readOnlyArgs, "touch /root-probe 2>/dev/null && echo WROTE || echo REFUSED"]);
    record(
      root.stdout.includes("REFUSED"),
      "Image root not writable",
      root.stdout.trim() || root.stderr.trim().split("\n")[0],
    );
  }

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
