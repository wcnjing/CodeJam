/**
 * Resolves `CODEX_BIN` to something Node can spawn WITHOUT a shell.
 *
 * The bug this fixes: on Windows a global npm install produces a `.cmd` shim
 * rather than a bare executable, and since the fix for CVE-2024-27980 Node
 * refuses to spawn `.cmd` or `.bat` without `shell: true`. A developer following
 * the README (`npm install --global @openai/codex`, then `npm run dev`) got
 * `spawn EINVAL` on every run under `RUNTIME_PROVIDER=local-process`.
 *
 * WHY NOT `shell: true`. `buildCodexArgs` puts `request.prompt` into argv, and
 * that prompt is the HTTP message body. With `shell: true` Node concatenates
 * argv into a cmd.exe command line without escaping, so a prompt of the form
 * `summarise & <command>` executes `<command>` on the host, outside the
 * container, as the server process. Verified by making it create a file.
 *
 * WHY NOT `cmd.exe /d /s /c` EITHER. Passing the arguments as an array does
 * contain injection - nine metacharacter payloads were tried and all were
 * contained - but cmd still performs environment expansion on the command line.
 * A prompt containing `%ARK_API_KEY%` comes back with the real key substituted
 * into it, because `childEnvironment()` puts that key in the child environment.
 * That would be a secret-disclosure channel introduced by a bug fix, in a
 * product that reports a secret-leak rate. It also mangles backslashes, so
 * `C:\Users\dev\repo` in a prompt arrives corrupted.
 *
 * So: no shell, ever, on this spawn. Resolve to a real executable where one
 * exists, and refuse to run where one does not.
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

export interface ResolvedBinary {
  /** What to spawn. */
  command: string;
  /** Arguments to place before the caller's own, e.g. a script path for node. */
  prefixArgs: string[];
  /** How it was resolved, for diagnostics and tests. */
  via: "direct" | "pathext" | "shim-exe" | "shim-script";
}

/** Extensions Windows can execute directly via CreateProcess. */
const DIRECTLY_SPAWNABLE = [".exe", ".com"];
/** Extensions that need a shell, which is exactly what must not be used. */
const SHELL_ONLY = [".cmd", ".bat"];

export class CodexBinaryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CodexBinaryError";
  }
}

function isFile(candidate: string): boolean {
  try {
    return statSync(candidate).isFile();
  } catch {
    return false;
  }
}

/** PATH entries, Windows-style, without the empty trailing segment. */
function pathEntries(): string[] {
  return (process.env.PATH ?? "").split(path.delimiter).filter((entry) => entry.length > 0);
}

/**
 * Finds `name` on PATH, preferring an extension Windows can spawn directly.
 *
 * Ordering is the whole point: a package that ships a real `.exe` alongside the
 * generated `.cmd` shim resolves to the `.exe`, and nothing else in this module
 * has to run.
 */
function searchPath(name: string): string | null {
  const directories = [process.cwd(), ...pathEntries()];
  const extensions = [...DIRECTLY_SPAWNABLE, ...SHELL_ONLY];
  for (const extension of extensions) {
    for (const directory of directories) {
      const candidate = path.join(directory, name + extension);
      if (isFile(candidate)) return candidate;
    }
  }
  return null;
}

/**
 * Reads an npm-generated `.cmd` shim and recovers what it actually invokes.
 *
 * npm's shims are generated from a template and reference their target relative
 * to `%dp0%` (the shim's own directory). Two shapes occur in practice: the shim
 * calls a real executable, or it calls node with a `.js` entry point.
 *
 * This parse is deliberately distrustful. Whatever it extracts must resolve to a
 * file that EXISTS and whose extension is one this module knows how to spawn.
 * Anything else returns null and the caller refuses to run. A shim template that
 * changes shape therefore produces the same actionable error as an unparseable
 * one - never a silently wrong executable.
 */
export function resolveShimTarget(shimPath: string): ResolvedBinary | null {
  let contents: string;
  try {
    contents = readFileSync(shimPath, "utf8");
  } catch {
    return null;
  }

  const shimDirectory = path.dirname(shimPath);
  const targets: string[] = [];
  // Every `%dp0%`-relative quoted path on a line that forwards arguments.
  for (const line of contents.split(/\r?\n/)) {
    if (!line.includes("%*")) continue;
    for (const match of line.matchAll(/"%dp0%[\\/]?([^"]+)"/g)) {
      const relative = match[1];
      if (relative) targets.push(path.resolve(shimDirectory, relative));
    }
  }
  if (targets.length === 0) return null;

  // A real executable the shim points at: spawn it directly.
  const executable = targets.find(
    (target) => DIRECTLY_SPAWNABLE.includes(path.extname(target).toLowerCase()) && isFile(target),
  );
  if (executable) return { command: executable, prefixArgs: [], via: "shim-exe" };

  // A node entry point: spawn THIS node with the script, which needs no shell.
  const script = targets.find(
    (target) => path.extname(target).toLowerCase() === ".js" && isFile(target),
  );
  if (script) return { command: process.execPath, prefixArgs: [script], via: "shim-script" };

  return null;
}

function refuse(codexBin: string, found: string): CodexBinaryError {
  return new CodexBinaryError(
    `CODEX_BIN resolved to "${found}", which Node cannot spawn without a shell.\n` +
      "This build will not use one: the Codex prompt is the HTTP message body and " +
      "reaches argv unescaped, so a shell here would turn a message into host " +
      "command execution, and cmd.exe would additionally expand ARK_API_KEY into " +
      "the prompt.\n" +
      "Two ways forward:\n" +
      `  1. Point CODEX_BIN at the real executable, e.g. the .exe inside the ` +
      `package's node_modules rather than the generated ${path.extname(found) || ".cmd"} shim.\n` +
      "  2. Use RUNTIME_PROVIDER=container, which spawns the container engine " +
      "rather than Codex directly and is unaffected.\n" +
      `(original CODEX_BIN: "${codexBin}")`,
  );
}

/**
 * Resolve `CODEX_BIN` for spawning.
 *
 * On anything other than Windows this returns the input unchanged: the bug and
 * the risk are both Windows-specific, and POSIX behaviour must not move.
 */
export function resolveCodexBinary(codexBin: string): ResolvedBinary {
  if (process.platform !== "win32") {
    return { command: codexBin, prefixArgs: [], via: "direct" };
  }

  const extension = path.extname(codexBin).toLowerCase();
  const looksLikePath = codexBin.includes("/") || codexBin.includes("\\");

  // An explicit path to something directly spawnable: nothing to do.
  if (DIRECTLY_SPAWNABLE.includes(extension)) {
    return { command: codexBin, prefixArgs: [], via: "direct" };
  }

  // An explicit path to a shim: try to see through it, else refuse.
  if (SHELL_ONLY.includes(extension)) {
    if (!existsSync(codexBin)) throw refuse(codexBin, codexBin);
    return resolveShimTarget(codexBin) ?? (() => { throw refuse(codexBin, codexBin); })();
  }

  // A bare name: search PATH, preferring a directly spawnable extension.
  if (!looksLikePath) {
    const found = searchPath(codexBin);
    if (!found) {
      // Not found at all. Leave it to spawn, whose ENOENT already says this
      // clearly; inventing a different error here would only obscure it.
      return { command: codexBin, prefixArgs: [], via: "direct" };
    }
    if (DIRECTLY_SPAWNABLE.includes(path.extname(found).toLowerCase())) {
      return { command: found, prefixArgs: [], via: "pathext" };
    }
    return resolveShimTarget(found) ?? (() => { throw refuse(codexBin, found); })();
  }

  // An extensionless explicit path. If a sibling shim exists, the same rules
  // apply; otherwise hand it to spawn unchanged.
  for (const candidate of [...DIRECTLY_SPAWNABLE, ...SHELL_ONLY].map((ext) => codexBin + ext)) {
    if (!isFile(candidate)) continue;
    if (DIRECTLY_SPAWNABLE.includes(path.extname(candidate).toLowerCase())) {
      return { command: candidate, prefixArgs: [], via: "pathext" };
    }
    return resolveShimTarget(candidate) ?? (() => { throw refuse(codexBin, candidate); })();
  }
  return { command: codexBin, prefixArgs: [], via: "direct" };
}
