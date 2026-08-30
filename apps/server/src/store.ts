import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import type { Database } from "./types.js";

const emptyDatabase = (): Database => ({
  version: 1,
  agents: [],
  messages: [],
  runs: [],
  policyEvents: [],
  approvals: [],
});

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
      const parsed = JSON.parse(raw) as Database;
      if (parsed.version !== 1 || !Array.isArray(parsed.agents)) {
        throw new Error("Unsupported database format");
      }
      this.data = { ...emptyDatabase(), ...parsed };
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
