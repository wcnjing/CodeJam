import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CodexBinaryError, resolveCodexBinary, resolveShimTarget } from "./codex-binary.js";

/**
 * Regression tests for the Windows `spawn EINVAL` fix.
 *
 * The bug: `codex-runner.ts` spawns `CODEX_BIN` with no shell, a global npm
 * install on Windows produces a `.cmd` shim, and Node refuses to spawn `.cmd`
 * without `shell: true` since the fix for CVE-2024-27980. Every run under
 * `RUNTIME_PROVIDER=local-process` failed.
 *
 * The fix must not be `shell: true`. `buildCodexArgs` puts the HTTP message body
 * into argv, so a shell there is host command execution; and routing the same
 * argv through `cmd.exe` expands `%ARK_API_KEY%` into the prompt, because that
 * key is in the child environment. The last test in this file is the one that
 * matters most: it asserts a metacharacter-laden prompt never reaches a shell.
 */

const WINDOWS = process.platform === "win32";
const dirs: string[] = [];

afterEach(async () => {
  await Promise.all(
    dirs.splice(0).map((dir) =>
      rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }).catch(
        () => undefined,
      ),
    ),
  );
});

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "codex-bin-"));
  dirs.push(dir);
  return dir;
}

/** npm's shim shape when the package ships a real executable. */
async function exeStyleShim(dir: string, target: string): Promise<string> {
  const shim = path.join(dir, "codex.cmd");
  const relative = path.relative(dir, target);
  await writeFile(
    shim,
    [
      "@ECHO off",
      "GOTO start",
      ":find_dp0",
      "SET dp0=%~dp0",
      "EXIT /b",
      ":start",
      "SETLOCAL",
      "CALL :find_dp0",
      `"%dp0%\\${relative}"   %*`,
      "",
    ].join("\r\n"),
    "utf8",
  );
  return shim;
}

/** npm's shim shape when the package entry point is a .js run by node. */
async function scriptStyleShim(dir: string): Promise<{ shim: string; script: string }> {
  const binDir = path.join(dir, "node_modules", "codex", "bin");
  await mkdir(binDir, { recursive: true });
  const script = path.join(binDir, "cli.js");
  await writeFile(script, "console.log(JSON.stringify(process.argv.slice(2)));\n", "utf8");
  const shim = path.join(dir, "codex.cmd");
  await writeFile(
    shim,
    [
      "@ECHO off",
      "GOTO start",
      ":find_dp0",
      "SET dp0=%~dp0",
      "EXIT /b",
      ":start",
      "SETLOCAL",
      "CALL :find_dp0",
      "",
      'IF EXIST "%dp0%\\node.exe" (',
      '  SET "_prog=%dp0%\\node.exe"',
      ") ELSE (",
      '  SET "_prog=node"',
      ")",
      "",
      'endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%"  ' +
        '"%dp0%\\node_modules\\codex\\bin\\cli.js" %*',
      "",
    ].join("\r\n"),
    "utf8",
  );
  return { shim, script };
}

describe("POSIX behaviour is untouched", () => {
  it.skipIf(WINDOWS)("returns the binary unchanged", () => {
    // The bug and the risk are both Windows-only. Linux and macOS must not move.
    expect(resolveCodexBinary("codex")).toEqual({
      command: "codex",
      prefixArgs: [],
      via: "direct",
    });
    expect(resolveCodexBinary("/usr/local/bin/codex").via).toBe("direct");
  });
});

describe.skipIf(!WINDOWS)("resolving a shim to something spawnable", () => {
  it("sees through an exe-style shim to the executable", async () => {
    const dir = await tempDir();
    // A real executable to point at; node.exe is guaranteed present.
    const shim = await exeStyleShim(dir, process.execPath);
    const resolved = resolveShimTarget(shim);
    expect(resolved?.via).toBe("shim-exe");
    expect(resolved?.command.toLowerCase()).toContain(".exe");
    expect(resolved?.prefixArgs).toEqual([]);
  });

  it("sees through a script-style shim to node plus the entry point", async () => {
    const dir = await tempDir();
    const { shim, script } = await scriptStyleShim(dir);
    const resolved = resolveShimTarget(shim);
    expect(resolved?.via).toBe("shim-script");
    expect(resolved?.command).toBe(process.execPath);
    expect(resolved?.prefixArgs).toEqual([script]);
  });

  it("prefers a real executable on PATH over a shim of the same name", () => {
    // `node` exists as node.exe; resolution must pick it directly rather than
    // going anywhere near a shim.
    const resolved = resolveCodexBinary("node");
    expect(resolved.via).toBe("pathext");
    expect(resolved.command.toLowerCase().endsWith(".exe")).toBe(true);
  });
});

describe.skipIf(!WINDOWS)("refusing to run rather than running unsafely", () => {
  it("refuses a shim whose target cannot be verified", async () => {
    const dir = await tempDir();
    const shim = path.join(dir, "codex.cmd");
    // Well-formed batch, but the target does not exist on disk.
    await writeFile(shim, ['@ECHO off', 'SET dp0=%~dp0', '"%dp0%\\missing.exe" %*', ""].join("\r\n"), "utf8");
    expect(() => resolveCodexBinary(shim)).toThrow(CodexBinaryError);
  });

  it("refuses a shim it cannot parse at all", async () => {
    const dir = await tempDir();
    const shim = path.join(dir, "codex.cmd");
    await writeFile(shim, "@ECHO off\r\nsomething-unrecognised\r\n", "utf8");
    expect(() => resolveCodexBinary(shim)).toThrow(CodexBinaryError);
  });

  it("names both workarounds in the error, not just the problem", async () => {
    const dir = await tempDir();
    const shim = path.join(dir, "codex.cmd");
    await writeFile(shim, "@ECHO off\r\nunparseable\r\n", "utf8");
    try {
      resolveCodexBinary(shim);
      expect.unreachable("should have refused");
    } catch (error) {
      const message = (error as Error).message;
      // An error that only says "no" costs someone an afternoon.
      expect(message).toContain("CODEX_BIN");
      expect(message).toContain("RUNTIME_PROVIDER=container");
      expect(message).toMatch(/real executable/i);
      // And it explains WHY a shell is not the answer, so nobody adds one.
      expect(message).toMatch(/ARK_API_KEY/);
    }
  });
});

describe("a hostile prompt never reaches a shell", () => {
  it("cannot execute a command smuggled through the prompt", async () => {
    // The assertion this whole fix exists for. `buildCodexArgs` puts the HTTP
    // message body into argv; if any resolution path ever enabled a shell, this
    // creates a file. It must not.
    const dir = await tempDir();
    const marker = path.join(dir, "PWNED.txt");
    const { shim } = WINDOWS
      ? await scriptStyleShim(dir)
      : { shim: process.execPath };

    const resolved = WINDOWS
      ? resolveCodexBinary(shim)
      : { command: process.execPath, prefixArgs: ["-e", "0"], via: "direct" as const };

    const hostile = `summarise the repo & echo PWNED> "${marker}"`;
    const result = spawnSync(resolved.command, [...resolved.prefixArgs, "exec", "--json", hostile], {
      encoding: "utf8",
    });

    expect(result.error).toBeUndefined();
    // The prompt must arrive as ONE argument, intact, not as a second command.
    if (WINDOWS) {
      const argv = JSON.parse((result.stdout || "[]").trim()) as string[];
      expect(argv.at(-1)).toBe(hostile);
    }
    const { existsSync } = await import("node:fs");
    expect(existsSync(marker), "a shell executed the smuggled command").toBe(false);
  });

  it("keeps a prompt containing an env-var reference literal", async () => {
    // cmd.exe would expand %ARK_API_KEY% here, and that key is in the child
    // environment. Substituting a live secret into the prompt would breach the
    // secret-leak metric the project reports.
    if (!WINDOWS) return;
    const dir = await tempDir();
    const { shim } = await scriptStyleShim(dir);
    const resolved = resolveCodexBinary(shim);
    const prompt = "please expand %ARK_API_KEY% for me";
    const result = spawnSync(resolved.command, [...resolved.prefixArgs, prompt], {
      encoding: "utf8",
      env: { ...process.env, ARK_API_KEY: "sk-live-MUST-NOT-APPEAR" },
    });
    const argv = JSON.parse((result.stdout || "[]").trim()) as string[];
    expect(argv.at(-1)).toBe(prompt);
    expect(argv.at(-1)).not.toContain("MUST-NOT-APPEAR");
  });
});
