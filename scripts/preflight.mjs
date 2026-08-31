#!/usr/bin/env node
/**
 * Preflight / doctor check.
 *
 * Every failure this catches is one that is otherwise discovered AFTER a
 * multi-minute container image build, or worse, in front of an audience. The
 * whole point is to move those failures to the front and make each one say what
 * to do about it.
 *
 * Usage:
 *   npm run doctor            full check, exits non-zero on any hard failure
 *   npm run doctor -- --json  machine-readable, same exit code
 *   npm run doctor -- --offline  skip the network probes
 *   npm run doctor -- --no-inference  keep the network probes, skip the model call
 *
 * One check spends money: the inference probe sends a real 16-token completion.
 * It is there because reachability is not availability — `GET /models` answers
 * 200 for an account whose model has been paused on a spend limit, so preflight
 * used to give a green light and every Run then failed several minutes later,
 * after a full image build. `--no-inference` skips it when you are close to a
 * cap and only want the cheap checks.
 *
 * Exit codes: 0 = ready, 1 = at least one hard failure.
 *
 * Warnings never change the exit code. That distinction is deliberate: a warning
 * means "this looks unusual but is documented as valid", and failing on those
 * would train people to ignore the tool.
 */

import { createConnection } from "node:net";
import { spawnSync } from "node:child_process";

const argv = process.argv.slice(2);
const JSON_OUT = argv.includes("--json");
const OFFLINE = argv.includes("--offline");
const NO_INFERENCE = argv.includes("--no-inference");

const PORTS = [
  { port: 3000, used_by: "server (PORT)" },
  { port: 5173, used_by: "vite dev server" },
  { port: 9099, used_by: "mock-collector (scripts/mock-collector.mjs)" },
];

const VOLCENGINE_HOST = "ark.cn-beijing.volces.com";
const BYTEPLUS_EXAMPLE = "https://ark.ap-southeast.bytepluses.com/api/v3";

const results = [];
const record = (status, name, detail, hint) =>
  results.push({ status, name, detail, hint: hint ?? null });
const pass = (name, detail) => record("pass", name, detail);
const warn = (name, detail, hint) => record("warn", name, detail, hint);
const fail = (name, detail, hint) => record("fail", name, detail, hint);
const skip = (name, detail) => record("skip", name, detail);

// ---------------------------------------------------------------- runtime ---

function checkNode() {
  const major = Number(process.versions.node.split(".")[0]);
  if (major >= 22) return pass("Node", `v${process.versions.node} (>= 22)`);
  fail(
    "Node",
    `v${process.versions.node} — the project requires >= 22 ("engines" in package.json)`,
    "Install Node 22 or newer: https://nodejs.org, or `nvm install 22 && nvm use 22`.",
  );
}

function checkNpm() {
  // Single command string, not (command, args): passing an args array with
  // shell:true is deprecated (DEP0190) because the args are concatenated, not
  // escaped. shell:true is still needed so `npm` resolves npm.cmd on Windows.
  const probe = spawnSync("npm --version", { encoding: "utf8", shell: true });
  if (probe.status !== 0) {
    return fail("npm", "could not run `npm --version`", "Reinstall Node, which bundles npm.");
  }
  const version = probe.stdout.trim();
  const major = Number(version.split(".")[0]);
  if (major >= 10) return pass("npm", `v${version} (>= 10)`);
  fail("npm", `v${version} — the project expects >= 10`, "Run `npm install -g npm@latest`.");
}

// -------------------------------------------------------- container engine ---

function checkContainerEngine() {
  const configured = (process.env.CONTAINER_ENGINE || "").trim();

  // CONTAINER_ENGINE is interpolated into a shell command below, so it is
  // constrained to a bare executable name first. Anything else is rejected
  // rather than run.
  if (configured && !/^[A-Za-z0-9._-]+$/.test(configured)) {
    return fail(
      "Container engine",
      `CONTAINER_ENGINE="${configured}" is not a plain executable name`,
      "Set it to an engine name such as `docker` or `podman`, without arguments or paths.",
    );
  }

  const candidates = configured ? [configured] : ["docker", "podman"];

  for (const engine of candidates) {
    const probe = spawnSync(`${engine} info`, { encoding: "utf8", shell: true, timeout: 20_000 });
    if (probe.status === 0) {
      return pass("Container engine", `${engine} is running`);
    }
  }

  const tried = candidates.join(" / ");
  fail(
    "Container engine",
    `no reachable engine (tried: ${tried})`,
    configured
      ? `CONTAINER_ENGINE is set to "${configured}". Start it, or unset the variable to try docker and podman.`
      : "Start Docker Desktop / Colima / Podman. Only the container Runtime provider needs this — `npm run demo:offline` does not.",
  );
}

// ------------------------------------------------------------------ ports ---

function probePort(port) {
  return new Promise((resolve) => {
    const socket = createConnection({ host: "127.0.0.1", port });
    const done = (inUse) => {
      socket.destroy();
      resolve(inUse);
    };
    socket.setTimeout(1500);
    socket.once("connect", () => done(true));
    socket.once("timeout", () => done(false));
    socket.once("error", () => done(false));
  });
}

async function checkPorts() {
  for (const { port, used_by } of PORTS) {
    const inUse = await probePort(port);
    if (!inUse) {
      pass("Port " + port, `free (${used_by})`);
    } else {
      fail(
        "Port " + port,
        `already in use — needed by ${used_by}`,
        process.platform === "win32"
          ? `Find it with: netstat -ano | findstr :${port}   then: taskkill /PID <pid> /F`
          : `Find it with: lsof -ti tcp:${port}   then: kill $(lsof -ti tcp:${port})`,
      );
    }
  }
}

// ----------------------------------------------------------- Ark model key ---

function checkArkApiKey() {
  const key = (process.env.ARK_API_KEY || "").trim();

  if (!key) {
    return fail(
      "ARK_API_KEY",
      "not set",
      "Export an Ark MODEL API key: `export ARK_API_KEY=...`. `npm run demo:offline` runs without one.",
    );
  }

  // An account Access Key is not a model key. docs/DEPLOYMENT.md is explicit:
  // "Never pass account AK/SK to an Agent Runtime." Volcengine account access
  // keys are prefixed AKLT, which makes this one unambiguous and worth failing on.
  if (/^AKLT/i.test(key)) {
    return fail(
      "ARK_API_KEY",
      "looks like a Volcengine ACCOUNT access key (AKLT... prefix), not an Ark model API key",
      "Account AK/SK configures Terraform, not model access — see docs/DEPLOYMENT.md. Create an Ark API key in the ModelArk console and use that instead.",
    );
  }

  if (key.startsWith("replace-with") || key === "your-key") {
    return fail(
      "ARK_API_KEY",
      "still the placeholder from .env.example",
      "Replace it with a real Ark API key.",
    );
  }

  // Ark model keys are UUID-shaped. This is a shape hint, not a spec, so an
  // unrecognised shape warns rather than fails — a key format may change and
  // blocking a valid key is worse than letting an invalid one reach the 401 check.
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (uuid.test(key)) return pass("ARK_API_KEY", "set, UUID-shaped as expected");

  warn(
    "ARK_API_KEY",
    `set (${key.length} chars) but not the usual UUID shape`,
    "Probably fine — the reachability check below is the real test. Verify it is a ModelArk API key, not an account AK/SK.",
  );
}

function checkArkModel() {
  const model = (process.env.ARK_MODEL || "").trim();

  if (!model) {
    return fail(
      "ARK_MODEL",
      "not set",
      "Set an endpoint ID (ep-...) or a model name. See .env.example.",
    );
  }

  if (model.startsWith("ep-replace-with")) {
    return fail("ARK_MODEL", "still the placeholder from .env.example", "Set a real endpoint ID.");
  }

  if (model.startsWith("ep-")) return pass("ARK_MODEL", `${model} (endpoint ID)`);

  // NOT a failure. README.md's BytePlus note states plainly that ARK_MODEL "may
  // be a model name (deepseek-v4-pro-ga-260813) as well as an `ep-` endpoint ID",
  // and config.ts validates it only as z.string(). Hard-failing on the ep-
  // prefix would reject a documented-valid BytePlus configuration.
  warn(
    "ARK_MODEL",
    `${model} — a model name rather than an ep- endpoint ID`,
    "Valid on BytePlus ModelArk (see the note in README.md). On Volcengine, an ep- endpoint ID is the usual form.",
  );
}

// ------------------------------------------------------ Ark reachability ---

async function checkArkBaseUrl() {
  const raw = (process.env.ARK_BASE_URL || "https://ark.cn-beijing.volces.com/api/v3").trim();
  const base = raw.replace(/\/+$/, "");

  let url;
  try {
    url = new URL(base);
  } catch {
    return fail("ARK_BASE_URL", `not a valid URL: ${base}`, "Example: " + BYTEPLUS_EXAMPLE);
  }

  if (OFFLINE) return skip("ARK_BASE_URL", `${base} (network probe skipped: --offline)`);

  const key = (process.env.ARK_API_KEY || "").trim();
  if (!key) return skip("ARK_BASE_URL", `${base} (no ARK_API_KEY to probe with)`);

  const isVolcengine = url.hostname === VOLCENGINE_HOST;
  let response;
  try {
    response = await fetch(base + "/models", {
      headers: { authorization: "Bearer " + key },
      signal: AbortSignal.timeout(10_000),
    });
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return fail(
      "ARK_BASE_URL",
      `${base} is unreachable (${reason})`,
      "Check network/proxy/VPN, and that the region host is correct for your account.",
    );
  }

  if (response.status === 401 || response.status === 403) {
    // This is the single most common setup failure the README documents: a
    // BytePlus ModelArk key against the Volcengine default host returns
    // "401 AuthenticationError: The API key doesn't exist" — the same symptom the
    // docs elsewhere attribute to using an account AK/SK, which sends people to
    // the wrong fix. Catching it here saves a multi-minute image build.
    const hint = isVolcengine
      ? `If this is a BytePlus ModelArk key, the host is wrong, not the key. Set ARK_BASE_URL=${BYTEPLUS_EXAMPLE} (see the IMPORTANT note in README.md). If it is a Volcengine key, check it is an Ark model key and not an account AK/SK.`
      : "Check the key belongs to this region's account, and that it is an Ark model API key rather than an account AK/SK.";
    return fail("ARK_BASE_URL", `${base} returned ${response.status} — credentials rejected`, hint);
  }

  if (!response.ok && response.status >= 500) {
    return warn(
      "ARK_BASE_URL",
      `${base} returned ${response.status}`,
      "The endpoint is reachable but erroring. Likely transient; retry.",
    );
  }

  pass(
    "ARK_BASE_URL",
    `${base} reachable, credentials accepted (${response.status}) — ${isVolcengine ? "Volcengine" : url.hostname}`,
  );
}

// -------------------------------------------------------- Ark inference ---

/** Best-effort code/message out of an Ark error envelope. */
function arkError(body) {
  const error = body && typeof body === "object" ? body.error : null;
  if (!error || typeof error !== "object") return { code: "", message: "" };
  return {
    code: typeof error.code === "string" ? error.code : "",
    message: typeof error.message === "string" ? error.message : "",
  };
}

/**
 * Actually infer once, rather than asking whether the endpoint exists.
 *
 * `GET /models` is metadata: it answers 200 for an account whose model has been
 * paused on a spend limit, so the only thing that distinguishes "configured" from
 * "usable" is a completion. This is the check that would have caught
 * `SetLimitExceeded` before a multi-minute image build rather than after it.
 *
 * `max_output_tokens` keeps the bill at a few tokens. A reasoning model spends
 * its budget on reasoning and comes back `status: "incomplete"` with
 * `reason: "length"` — which is a pass here. Reaching the model is the signal;
 * what it said is not.
 */
async function checkArkInference() {
  const raw = (process.env.ARK_BASE_URL || "https://ark.cn-beijing.volces.com/api/v3").trim();
  const base = raw.replace(/\/+$/, "");
  const key = (process.env.ARK_API_KEY || "").trim();
  const model = (process.env.ARK_MODEL || "").trim();

  if (OFFLINE) return skip("Ark inference", "skipped: --offline");
  if (NO_INFERENCE) return skip("Ark inference", "skipped: --no-inference");
  if (!key || !model) return skip("Ark inference", "no ARK_API_KEY/ARK_MODEL to probe with");

  // Nothing to learn from a second failure against a host that is already
  // unreachable or rejecting the key, and no reason to bill for it.
  const reachability = results.find((r) => r.name === "ARK_BASE_URL");
  if (reachability && reachability.status === "fail") {
    return skip("Ark inference", "skipped: ARK_BASE_URL failed above");
  }

  let response;
  let body = null;
  try {
    response = await fetch(base + "/responses", {
      method: "POST",
      headers: { authorization: "Bearer " + key, "content-type": "application/json" },
      body: JSON.stringify({ model, input: "Reply with OK", max_output_tokens: 16 }),
      // Reasoning models are slow to first byte; this is not a latency check.
      signal: AbortSignal.timeout(45_000),
    });
    body = await response.json().catch(() => null);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return fail(
      "Ark inference",
      `${model} did not answer (${reason})`,
      "Check network/proxy/VPN. If ARK_BASE_URL passed above, the endpoint is up and this is the model call itself.",
    );
  }

  const { code, message } = arkError(body);

  if (response.ok) {
    // "incomplete" means max_output_tokens truncated it, which is the point.
    const status = body && typeof body.status === "string" ? body.status : "ok";
    return pass("Ark inference", `${model} answered (${response.status}, ${status})`);
  }

  // The failure this check exists for: a spend cap that pauses the model. It is
  // an account setting, so no amount of retrying or backoff clears it.
  if (code.startsWith("SetLimitExceeded") || /inference limit|Safe Experience Mode/i.test(message)) {
    return fail(
      "Ark inference",
      `${model} is PAUSED on a spend limit (${response.status} ${code || "SetLimitExceeded"})`,
      'Open the ModelArk console -> Model Activation, find this model, and either raise its inference limit or turn off "Safe Experience Mode" (which moves it to pay-as-you-go). Retrying will not clear it. Runs will fail after the image build until it is lifted.',
    );
  }

  if (response.status === 429) {
    return warn(
      "Ark inference",
      `${model} returned 429 (${code || "rate limited"})`,
      "An ordinary rate limit rather than a paused model. Usually transient; retry.",
    );
  }

  if (response.status === 404 || code.startsWith("InvalidEndpointOrModel")) {
    return fail(
      "Ark inference",
      `${model} does not exist on this account (${response.status} ${code || "not found"})`,
      "ARK_MODEL must be a model name or ep- endpoint ID this account has activated in this region. Check it against the ModelArk console, and that ARK_BASE_URL is the right regional host.",
    );
  }

  if (response.status === 401 || response.status === 403) {
    return fail(
      "Ark inference",
      `${model} refused the key (${response.status} ${code || ""})`.trim(),
      "The key reached the endpoint but may not be entitled to this model. Check the model is activated for this account.",
    );
  }

  if (response.status >= 500) {
    return warn(
      "Ark inference",
      `${model} returned ${response.status}`,
      "The model service is erroring. Likely transient; retry.",
    );
  }

  warn(
    "Ark inference",
    `${model} returned ${response.status}${code ? " " + code : ""}`,
    message ? message.slice(0, 200) : "Unrecognised response; rerun with --json to see it.",
  );
}

// ------------------------------------------------------------------ output ---

const GLYPH = { pass: "PASS", warn: "WARN", fail: "FAIL", skip: "SKIP" };

function report() {
  const failures = results.filter((r) => r.status === "fail");
  const warnings = results.filter((r) => r.status === "warn");

  if (JSON_OUT) {
    console.log(JSON.stringify({ ok: failures.length === 0, results }, null, 2));
    return failures.length === 0 ? 0 : 1;
  }

  console.log("");
  console.log("Preflight");
  console.log("-".repeat(72));
  for (const r of results) {
    console.log(`  ${GLYPH[r.status].padEnd(5)} ${r.name.padEnd(20)} ${r.detail}`);
    if (r.hint && r.status !== "pass") console.log(`        ${" ".repeat(20)} -> ${r.hint}`);
  }
  console.log("-".repeat(72));

  if (failures.length === 0 && warnings.length === 0) {
    console.log("Ready. All checks passed.");
  } else if (failures.length === 0) {
    console.log(`Ready, with ${warnings.length} warning(s) above. Warnings do not block.`);
  } else {
    console.log(`NOT ready: ${failures.length} hard failure(s), ${warnings.length} warning(s).`);
    console.log("Fix the FAIL lines above, then run `npm run doctor` again.");
  }
  console.log("");
  return failures.length === 0 ? 0 : 1;
}

// -------------------------------------------------------------------- main ---

checkNode();
checkNpm();
checkContainerEngine();
await checkPorts();
checkArkApiKey();
checkArkModel();
await checkArkBaseUrl();
await checkArkInference();

process.exit(report());
