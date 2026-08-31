import { appendFile, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import type {
  Database,
  DatabaseV1,
  DatabaseV2,
  DatabaseV3,
  PolicyDecision,
} from "./types.js";

const CURRENT_VERSION = 4;

const emptyDatabase = (): Database => ({
  version: CURRENT_VERSION,
  agents: [],
  messages: [],
  runs: [],
  policyEvents: [],
  approvals: [],
  allowlist: [],
});

/**
 * Shape as found on disk: the version is whatever release last wrote it, and
 * only `version` is trustworthy until `migrate` has walked the value forward.
 * The fields are Partial so older shapes (which lack e.g. v4's `allowlist`)
 * are still valid transports; each migration step casts to its own version's
 * real shape before touching a field.
 */
type StoredDatabase = Omit<Partial<Database>, "version"> & { version: number };

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
function migrateV1ToV2(v1: DatabaseV1): DatabaseV2 {
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
  // v2 -> v3: policy events leave the blob for an append-only log beside it.
  // The step only bumps the version and carries the events through untouched;
  // `initialize` lifts them into the log and clears them from the in-memory
  // copy. Adoption is deliberately NOT done here -- a migration step is pure and
  // synchronous by contract, and writing a file from inside one would make the
  // registry a place where I/O hides.
  2: (database) => ({ ...(database as unknown as DatabaseV2), version: 3 }),
  // v3 -> v4: the standing allowlist override arrives. Every existing approval
  // predates the "approve and widen" option, so its record is stamped `null`
  // rather than left to imply a widening that never happened.
  3: (database) => {
    const v3 = database as unknown as DatabaseV3;
    return {
      ...v3,
      version: 4,
      allowlist: [],
      approvals: v3.approvals.map((approval) => ({
        ...approval,
        allowlistWidened: null,
      })),
    };
  },
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

/**
 * The shortest interval between two rewrites of the log file.
 *
 * Expired events leave memory the moment they expire, so nothing past retention
 * is ever readable. Reclaiming the DISK costs a full rewrite, which is O(events
 * stored); doing one per expiry would put back exactly the linear term this
 * class removed. Rate-limiting by wall clock rather than by a count is what
 * keeps the amortised per-append cost flat regardless of how many events exist:
 * a burst of a million appends still pays for at most one rewrite a minute.
 */
const COMPACTION_INTERVAL_MS = 60_000;

/**
 * The audit log, appended to rather than rewritten (TM-OPS-001).
 *
 * Recording one policy decision used to cost O(events already stored): every
 * `mutate()` cloned the whole Database, pruned it and re-serialised it.
 * Measured in CI across three runners that was 0.31-1.08 ms at zero events and
 * 14.16-17.59 ms at 5,000, linear at r-squared 0.9995-0.9999 -- a property of
 * the code, not of a machine. Against a ~60 us decision, recording it cost
 * several hundred times more than making it, and the multiple grew unbounded.
 *
 * Both cheap fixes capped the log by discarding audit records. For a project
 * whose thesis is trustworthy evidence that is a liability rather than a fix,
 * and a cap does not remove the linear term in any case -- it moves the ceiling.
 * So events move into their own append-only JSONL file instead, one per line.
 * Appending is a single `appendFile`: no clone, no re-serialisation of prior
 * events, no full-file rewrite. Nothing is discarded to achieve it.
 *
 * Ordering is audit-first: the event is appended BEFORE the state mutation it
 * accompanies, so a crash between them leaves a record whose state update never
 * landed, and never the reverse.
 *
 * Retention applies continuously, not only at load. Age is a property of a
 * record -- it does not change because somebody wrote another one -- but that
 * argument only justifies not RE-EVALUATING every stored event on every write.
 * It does not justify waiting for a restart: a server that runs for months
 * would otherwise serve, and keep, records long past their retention window.
 * So expiry is applied on every append and every read, and the FILE is rewritten
 * on a bounded schedule (see `enforceRetention`), which keeps the write path
 * O(1) in the number of events already stored -- the property this class exists
 * to provide.
 */
class PolicyEventLog {
  private events: PolicyDecision[] = [];
  private lastCompactedAt = 0;

  constructor(
    private readonly filePath: string,
    private readonly retentionMs: number,
  ) {}

  /**
   * `adopted` carries events lifted out of a pre-v3 database blob. Adoption is
   * idempotent BY EVENT ID: the migration writes the events here before the
   * database that carried them is rewritten without them, so a crash between
   * those two steps leaves a store that will offer the same events again on the
   * next start. Re-adopting them must be a no-op, not a duplicated audit trail.
   */
  async load(adopted: PolicyDecision[] = []): Promise<void> {
    const onDisk: PolicyDecision[] = [];
    try {
      const raw = await readFile(this.filePath, "utf8");
      for (const line of raw.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          onDisk.push(JSON.parse(trimmed) as PolicyDecision);
        } catch {
          // One unparseable line must not cost the whole audit trail. A
          // truncated final line is the expected case after a crash mid-append,
          // and every line before it is still perfectly good evidence.
        }
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const cutoff = Date.now() - this.retentionMs;
    const seen = new Set<string>();
    const kept: PolicyDecision[] = [];
    for (const event of [...onDisk, ...adopted]) {
      if (new Date(event.decidedAt).getTime() < cutoff) continue;
      if (seen.has(event.id)) continue;
      seen.add(event.id);
      kept.push(event);
    }
    // Adopted events predate everything appended since, so the merged sequence
    // is not necessarily in time order. Sorting it once here is what lets the
    // running server drop expirations as a PREFIX rather than rescanning the
    // whole array -- an O(n log n) at startup buying O(1) amortised afterwards.
    kept.sort((a, b) => new Date(a.decidedAt).getTime() - new Date(b.decidedAt).getTime());
    this.events = kept;
    if (kept.length !== onDisk.length || adopted.length > 0) await this.compact();
  }

  /** O(1) amortised in the number of events already stored. The whole point. */
  async append(event: PolicyDecision): Promise<void> {
    this.events.push(event);
    await appendFile(this.filePath, JSON.stringify(event) + "\n", {
      encoding: "utf8",
      mode: 0o600,
    });
    await this.enforceRetention();
  }

  /**
   * Events are immutable once written, so readers get a shallow copy -- of the
   * events that are still within retention. Enforcing it here as well as on
   * append is what makes the guarantee hold on an idle server: no append, no
   * restart, and still nothing past the window is returned.
   */
  all(): PolicyDecision[] {
    this.dropExpired();
    return this.events.slice();
  }

  /** Deleting an agent's evidence is inherently O(n); it is not on the hot path. */
  async removeForAgent(agentId: string): Promise<void> {
    const before = this.events.length;
    this.events = this.events.filter((event) => event.agentId !== agentId);
    if (this.events.length !== before) await this.compact();
  }

  /**
   * Drop everything past the retention window from memory.
   *
   * Events are held in time order (appends are chronological; `load` sorts the
   * one case that is not), so the expired ones are a prefix and the scan stops
   * at the first survivor. Each event is dropped exactly once over the life of
   * the process, which is what makes this O(1) amortised per append rather than
   * the O(events stored) rescan that per-write pruning used to cost.
   */
  private dropExpired(): number {
    const cutoff = Date.now() - this.retentionMs;
    let expired = 0;
    while (
      expired < this.events.length &&
      new Date(this.events[expired]!.decidedAt).getTime() < cutoff
    ) {
      expired += 1;
    }
    if (expired > 0) this.events = this.events.slice(expired);
    return expired;
  }

  private async enforceRetention(): Promise<void> {
    if (this.dropExpired() === 0) return;
    if (Date.now() - this.lastCompactedAt < COMPACTION_INTERVAL_MS) return;
    await this.compact();
  }

  private async compact(): Promise<void> {
    const temporaryPath = this.filePath + ".tmp";
    const body = this.events.map((event) => JSON.stringify(event)).join("\n");
    await writeFile(temporaryPath, this.events.length ? body + "\n" : "", {
      encoding: "utf8",
      mode: 0o600,
    });
    await rename(temporaryPath, this.filePath);
    this.lastCompactedAt = Date.now();
  }
}

export class JsonStore {
  private data: Database = emptyDatabase();
  private queue: Promise<void> = Promise.resolve();
  private readonly log: PolicyEventLog;

  constructor(
    private readonly filePath: string,
    private readonly retentionDays: number = 90,
  ) {
    this.log = new PolicyEventLog(
      filePath.replace(/\.json$/, "") + ".policy-events.jsonl",
      retentionDays * 24 * 60 * 60 * 1000,
    );
  }

  async initialize(): Promise<void> {
    await mkdir(path.dirname(this.filePath), { recursive: true });
    let adopted: PolicyDecision[] = [];
    let migrated = false;
    try {
      const raw = await readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw) as StoredDatabase;
      if (!Array.isArray(parsed.agents)) {
        throw new Error("Unsupported database format");
      }
      const walked = migrate(parsed);
      migrated = walked.migrated;
      // Lift any events the migration carried through into the log. Dropping
      // them would make an upgrade destroy the audit trail, which is a worse
      // bug than the performance defect this release fixes.
      adopted = walked.database.policyEvents ?? [];
      this.data = {
        ...emptyDatabase(),
        ...walked.database,
        policyEvents: [],
        version: CURRENT_VERSION,
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
      await this.persist();
    }
    // Adopt FIRST, then record the upgrade. The database is the only remaining
    // copy of a pre-v3 record's policy events, so writing it back as v3 with an
    // empty `policyEvents` before the log has them durably is a window in which
    // a crash -- or an EACCES/ENOSPC on the JSONL -- destroys the audit trail
    // outright, with nothing left for the next start to recover from. In this
    // order the worst case is a v2 database whose events are already in the log,
    // and re-adopting them is a no-op because `load` dedupes by event id.
    await this.log.load(adopted);
    // Write the upgrade back once, so the labelling survives a crash and the
    // next start is not a second migration of the same records.
    if (migrated) await this.persist();
  }

  snapshot(): Database {
    return { ...structuredClone(this.data), policyEvents: this.log.all() };
  }

  /** Record one policy decision. Its cost does not depend on how many exist. */
  async appendPolicyDecision(event: PolicyDecision): Promise<void> {
    await this.log.append(event);
  }

  async removePolicyEventsForAgent(agentId: string): Promise<void> {
    await this.log.removeForAgent(agentId);
  }

  async mutate<T>(mutation: (database: Database) => T | Promise<T>): Promise<T> {
    let result!: T;
    const operation = this.queue.then(async () => {
      // `next.policyEvents` stays empty, and that is the fix. Materialising the
      // log into every mutation -- even only to support callers that push into
      // it -- would reintroduce an O(events already stored) copy on the write
      // path, which is the exact cost being removed. Anything a mutation does
      // push is still adopted below rather than dropped, so a caller that has
      // not migrated loses performance, never records.
      const next = structuredClone(this.data);
      result = await mutation(next);
      const appended = next.policyEvents;
      next.policyEvents = [];
      this.prune(next);
      // Audit first, and this ordering is the guarantee, not an implementation
      // detail. Persisting the state before the evidence meant a failed append
      // -- ENOSPC, EACCES, EROFS -- rejected the mutation while the state it
      // describes was already durable, so a restart came back to a run or a
      // message with no policy event beside it. In this order a failure at any
      // point leaves at most an event whose state update never landed, which is
      // the direction an audit trail is allowed to be wrong in.
      for (const event of appended) await this.log.append(event);
      await this.persist(next);
      this.data = next;
    });
    this.queue = operation.catch(() => undefined);
    await operation;
    return result;
  }

  /**
   * Bounds the approval trail (TM-OPS-001). Policy events are no longer pruned
   * here — they are compacted when the log loads, because retention is a policy
   * about AGE, and age does not change because somebody wrote a record. Pruning
   * them per write was part of what made recording one decision O(n). A pending
   * approval is live state (a held run waiting on a human), not history, so it
   * is exempt regardless of age — it becomes eligible only once resolved.
   */
  private prune(database: Database): void {
    const cutoff = Date.now() - this.retentionDays * 24 * 60 * 60 * 1000;
    database.approvals = database.approvals.filter(
      (approval) =>
        approval.status === "pending" ||
        approval.resolvedAt === null ||
        new Date(approval.resolvedAt).getTime() >= cutoff,
    );
  }

  private async persist(data: Database = this.data): Promise<void> {
    const temporaryPath = this.filePath + ".tmp";
    const onDisk = { ...data, policyEvents: [] };
    await writeFile(temporaryPath, JSON.stringify(onDisk, null, 2) + "\n", {
      encoding: "utf8",
      mode: 0o600,
    });
    await rename(temporaryPath, this.filePath);
  }
}
