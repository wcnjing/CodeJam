import { afterEach, describe, expect, it } from "vitest";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const script = fileURLToPath(new URL("../../../scripts/start-local-poc.sh", import.meta.url));
const temporaryDirectories: string[] = [];

function executable(file: string, source: string): void {
  writeFileSync(file, source, "utf8");
  chmodSync(file, 0o755);
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("start-local-poc.sh", () => {
  it("loads missing values from its env file, preserves shell overrides, and builds the broker", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "sentinel-start-poc-"));
    temporaryDirectories.push(directory);
    const fakeBin = path.join(directory, "bin");
    const state = path.join(directory, "state");
    const log = path.join(directory, "calls.log");
    const envFile = path.join(directory, "review.env");

    mkdirSync(fakeBin);
    executable(
      path.join(fakeBin, "sentinel-test-engine"),
      [
        "#!/usr/bin/env bash",
        'printf \'engine:%s\\n\' "$*" >> "$SENTINEL_TEST_LOG"',
        'case "$1" in',
        "  info|build|run|rm) exit 0 ;;",
        "  ps) exit 0 ;;",
        "esac",
        "exit 0",
        "",
      ].join("\n"),
    );
    executable(
      path.join(fakeBin, "npm"),
      [
        "#!/usr/bin/env bash",
        'printf \'npm:%s|model=%s|key=%s\\n\' "$*" "$ARK_MODEL" "$ARK_API_KEY" >> "$SENTINEL_TEST_LOG"',
        "exit 0",
        "",
      ].join("\n"),
    );
    writeFileSync(
      envFile,
      [
        "ARK_API_KEY=key-from-env-file",
        "ARK_MODEL=model-from-env-file",
        "CONTAINER_EGRESS_BROKER_IMAGE=fixture-broker:local",
        "",
      ].join("\n"),
      "utf8",
    );

    const environment = { ...process.env };
    delete environment.ARK_API_KEY;
    delete environment.CONTAINER_EGRESS_BROKER_IMAGE;
    Object.assign(environment, {
      ARK_MODEL: "model-from-shell",
      CONTAINER_ENGINE: "sentinel-test-engine",
      CONTAINER_RUNTIME_IMAGE: "fixture-runtime:local",
      LOCAL_POC_DATA_ROOT: state,
      LOCAL_POC_ENV_FILE: envFile,
      SENTINEL_TEST_LOG: log,
      PATH: fakeBin + path.delimiter + (process.env.PATH ?? ""),
    });

    const result = spawnSync("bash", [script], {
      cwd: path.dirname(script),
      env: environment,
      encoding: "utf8",
      timeout: 10_000,
    });

    expect(result.status, result.stderr).toBe(0);
    const calls = readFileSync(log, "utf8");
    expect(calls).toContain(
      "engine:build --file Dockerfile.egress-broker --build-arg " +
        "NODE_IMAGE=node:22-bookworm-slim --tag fixture-broker:local .",
    );
    expect(calls).toContain("npm:start|model=model-from-shell|key=key-from-env-file");
  });
});
