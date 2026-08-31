import { randomBytes } from "node:crypto";
import { lstat, open, realpath, rename, rm } from "node:fs/promises";
import path from "node:path";

/**
 * Writes a file into a directory the Agent can also write to, without ever
 * following a symlink the Agent may have planted.
 *
 * The Agent workspace is shared ground: the Agent owns it, and the host process
 * also writes into it (AGENTS.md, the protected fixture, .gitignore, README.md).
 * A plain `writeFile` follows symlinks, so an Agent that replaces AGENTS.md with
 * a link to `.data/launchpad.json` turns the next `PATCH /api/agents/:id` into a
 * host-privileged write over our own audit store — with content the API caller
 * supplies. Every host write into Agent-controlled ground goes through here.
 *
 * Three defences, because any one alone is bypassable:
 *
 * 1. `realpath` the destination's parent and require it to stay under `root`.
 *    Catches a symlinked intermediate directory and any `..` that escapes,
 *    both of which a check on the unresolved path would miss.
 * 2. `lstat` the destination itself — never `stat`, which follows the link we
 *    are trying to detect — and refuse anything present that is not a regular
 *    file: a symlink, directory, device, or FIFO.
 * 3. Write a same-directory temp file with `O_EXCL` and `rename` it over the
 *    destination. `O_EXCL` fails rather than following a link planted at the
 *    temp name, and `rename` replaces the destination's own directory entry
 *    instead of resolving it — so even a symlink swapped in between steps 2
 *    and 3 cannot redirect the write.
 *
 * Steps 1 and 2 are checks and therefore racy on their own; step 3 is what
 * actually makes the write safe. The checks stay because they turn a race into
 * a clear error instead of an `EEXIST` from the rename.
 */
export async function safeWriteFile(
  root: string,
  destinationPath: string,
  content: string,
  options: { mode?: number } = {},
): Promise<void> {
  const resolvedRoot = await realpath(root);

  let resolvedDir: string;
  try {
    resolvedDir = await realpath(path.dirname(destinationPath));
  } catch {
    throw new Error("Refusing to write: " + destinationPath + " has no existing parent directory");
  }
  if (resolvedDir !== resolvedRoot && !resolvedDir.startsWith(resolvedRoot + path.sep)) {
    throw new Error(
      "Refusing to write outside the workspace root: " +
        destinationPath +
        " resolves into " +
        resolvedDir,
    );
  }

  const existing = await lstat(destinationPath).catch(() => null);
  if (existing && !existing.isFile()) {
    throw new Error(
      "Refusing to overwrite a non-regular file at " +
        destinationPath +
        " (symlink, directory, device, or FIFO)",
    );
  }

  // The temp file is created fresh and renamed over the destination, so it
  // carries its own mode rather than inheriting the one it replaces. Without
  // this, omitting `mode` silently widens an existing 0600 file to 0644 — a
  // rewrite must never be the thing that opens a file up.
  const mode = options.mode ?? (existing ? existing.mode & 0o777 : 0o644);

  const temporaryPath = path.join(
    resolvedDir,
    ".safe-write-" + randomBytes(8).toString("hex") + ".tmp",
  );
  const handle = await open(temporaryPath, "wx", mode);
  try {
    await handle.writeFile(content, "utf8");
  } finally {
    await handle.close();
  }

  try {
    await rename(temporaryPath, path.join(resolvedDir, path.basename(destinationPath)));
  } catch (error) {
    await rm(temporaryPath, { force: true });
    throw error;
  }
}
