import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import type { Database, DatabaseV1 } from "./types.js";

const CURRENT_VERSION = 2;

const emptyDatabase = (): Database => ({
  version: CURRENT_VERSION,
  agents: [],
  messages: [],
  runs: [],
  policyEvents: [],
  approvals: [],
});

/**
 * Shape as found on disk: the version is whatever release last wrote it, and
 * only `version` is trustworthy until `migrate` has walked the value forward.
 * The collection types are the current ones purely so this stays a usable
 * transport type through the chain — each step casts to its own version's real
 * shape before touching a field.
 */
type StoredDatabase = Omit<Database, "version"> & { version: number };

/**
 * v1 -> v2. Before v2 the approver was a free-text `actor` field on the request
 * body, so any name a v1 record carries was asserted by the client rather than
 * derived from its credential. Stamping those "self-asserted" is the whole
 * point of the bump: without it, migrated records would sit beside
 * credential-derived ones in the same shape, and the guarantee the type
 * documents would be false for part of the store with no way to tell which.
 * Retention keeps approvals for 90 days, so a real deployment carries them
 * across the upgrade.
 */
function migrateV1ToV2(v1: DatabaseV1): Database {
  return {
    ...v1,
    version: 2,
    approvals: v1.approvals.map((approval) => ({
      ...approval,
      resolvedByAttribution: approval.resolvedBy === null ? null : ("self-asserted" as const),
    })),
  };
}

/**
 * Each step takes the previous version's own type and returns the next, so a
 * field added at v3 cannot be silently assumed present on a v1 record. Add a
 * step here rather than widening one that already shipped: the older shapes are
 * frozen history, and the compiler is what keeps a later migration honest about
 * what actually existed when the record was written.
 */
type MigrationStep = (database: StoredDatabase) => StoredDatabase;

const MIGRATIONS: Record<number, MigrationStep> = {
  // The cast lives here and only here. Parsed JSON is untyped by nature, so one
  // assertion at that boundary is unavoidable; keeping it in the registry means
  // each migrator below is still checked against the real shape of its own
  // version, which is the property worth having.
  1: (database) => migrateV1ToV2(database as unknown as DatabaseV1),
};

/** Walks a stored database forward to CURRENT_VERSION, one step per version. */
function migrate(parsed: StoredDatabase): { database: Database; migrated: boolean } {
  let current = parsed;
  let migrated = false;
  while (current.version !== CURRENT_VERSION) {
    const step = MIGRATIONS[current.version];
    if (!step) {
      throw new Error("Unsupported database format");
    }
    current = step(current as never);
    migrated = true;
  }
  return { database: current as unknown as Database, migrated };
}

export class JsonStore {
  private data: Database = emptyDatabase();
  private queue: Promise<void> = Promise.resolve();

  constructor(
    private readonly filePath: string,
    private readonly retentionDays: number = 90,
  ) {}

  async initialize(): Promise<void> {
    await mkdir(path.dirname(this.filePath), { recursive: true });
    try {
      const raw = await readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw) as StoredDatabase;
      if (!Array.isArray(parsed.agents)) {
        throw new Error("Unsupported database format");
      }
      const { database, migrated } = migrate(parsed);
      this.data = { ...emptyDatabase(), ...database, version: CURRENT_VERSION };
      // Write the upgrade back once, so the labelling survives a crash and the
      // next start is not a second migration of the same records.
      if (migrated) await this.persist();
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
      await this.persist();
    }
  }

  snapshot(): Database {
    return structuredClone(this.data);
  }

  async mutate<T>(mutation: (database: Database) => T | Promise<T>): Promise<T> {
    let result!: T;
    const operation = this.queue.then(async () => {
      const next = structuredClone(this.data);
      result = await mutation(next);
      this.prune(next);
      await this.persist(next);
      this.data = next;
    });
    this.queue = operation.catch(() => undefined);
    await operation;
    return result;
  }

  /**
   * Bounds the audit trail (TM-OPS-001): policyEvents/approvals are the only
   * things this store appends to without a corresponding delete elsewhere, so
   * they are the only arrays pruned here. A pending approval is live state (a
   * held run waiting on a human), not history, so it is exempt regardless of
   * age — it becomes eligible only once resolved.
   */
  private prune(database: Database): void {
    const cutoff = Date.now() - this.retentionDays * 24 * 60 * 60 * 1000;
    database.policyEvents = database.policyEvents.filter(
      (event) => new Date(event.decidedAt).getTime() >= cutoff,
    );
    database.approvals = database.approvals.filter(
      (approval) =>
        approval.status === "pending" ||
        approval.resolvedAt === null ||
        new Date(approval.resolvedAt).getTime() >= cutoff,
    );
  }

  private async persist(data: Database = this.data): Promise<void> {
    const temporaryPath = this.filePath + ".tmp";
    await writeFile(temporaryPath, JSON.stringify(data, null, 2) + "\n", {
      encoding: "utf8",
      mode: 0o600,
    });
    await rename(temporaryPath, this.filePath);
  }
}
