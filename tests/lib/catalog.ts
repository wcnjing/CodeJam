/**
 * Case catalog loader.
 *
 * All case files live in tests/cases/*.json and are merged into one catalog.
 * Each file is an object `{ "source": "...", "cases": [TestCase...] }`.
 * The loader validates the schema and tag vocabulary so a malformed case
 * fails the run loudly instead of silently skewing a score.
 */

import { existsSync } from "node:fs";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertKnownTags } from "./tags.js";
import type { TestCase } from "./types.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));

/**
 * Cases dir. In the source layout (dev/CLI) the catalog sits at tests/cases;
 * in the built package the build copies it next to the compiled output
 * (tests/dist/cases). Prefer the built copy, fall back to the source.
 */
function resolveCasesDir(): string {
  const built = path.resolve(HERE, "cases");
  return existsSync(built) ? built : path.resolve(HERE, "..", "cases");
}

export const CASES_DIR = resolveCasesDir();

export interface CaseFile {
  source: string;
  cases: TestCase[];
}

function assertCase(value: unknown, file: string, fileSource: string): TestCase {
  if (typeof value !== "object" || value === null) {
    throw new Error(file + ": case is not an object");
  }
  const c = value as Record<string, unknown>;
  if (typeof c["id"] !== "string" || c["id"].length === 0) {
    throw new Error(file + ": case missing string id");
  }
  if (typeof c["command"] !== "string" || c["command"].length === 0) {
    throw new Error(file + ": case " + c["id"] + " missing command");
  }
  if (c["label"] !== "malicious" && c["label"] !== "benign") {
    throw new Error(file + ": case " + c["id"] + " bad label");
  }
  if (c["expected"] !== "deny" && c["expected"] !== "allow") {
    throw new Error(file + ": case " + c["id"] + " bad expected");
  }
  if (!Array.isArray(c["tags"]) || c["tags"].some((t) => typeof t !== "string")) {
    throw new Error(file + ": case " + c["id"] + " bad tags");
  }
  assertKnownTags(c["tags"] as string[]);
  if (typeof c["category"] !== "string" || c["category"].length === 0) {
    throw new Error(file + ": case " + c["id"] + " missing category");
  }
  return {
    id: c["id"] as string,
    command: c["command"] as string,
    label: c["label"] as TestCase["label"],
    expected: c["expected"] as TestCase["expected"],
    tags: c["tags"] as string[],
    category: c["category"] as string,
    wrapped: typeof c["wrapped"] === "boolean" ? (c["wrapped"] as boolean) : undefined,
    // Per-entry provenance when present, else the file-level source — so every
    // case stays auditable to its origin.
    source: typeof c["source"] === "string" ? (c["source"] as string) : fileSource,
    threatIds: Array.isArray(c["threatIds"]) ? (c["threatIds"] as string[]) : undefined,
    middleware: Array.isArray(c["middleware"]) ? (c["middleware"] as string[]) : undefined,
    note: typeof c["note"] === "string" ? (c["note"] as string) : undefined,
  };
}

export async function loadCaseFiles(): Promise<CaseFile[]> {
  const entries = await readdir(CASES_DIR);
  const files = entries
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => path.join(CASES_DIR, name));
  const result: CaseFile[] = [];
  for (const file of files) {
    const raw = JSON.parse(await readFile(file, "utf8")) as unknown;
    if (typeof raw !== "object" || raw === null || !Array.isArray((raw as { cases?: unknown }).cases)) {
      // Non-catalog JSON (e.g. a design artifact dropped in the folder) is
      // skipped rather than fatal, so stray files cannot break the suite.
      console.warn("skipping non-catalog JSON: " + file);
      continue;
    }
    const parsed = raw as { source?: unknown; cases: unknown[] };
    const fileSource = typeof parsed.source === "string" ? parsed.source : file;
    const cases = parsed.cases.map((entry) => assertCase(entry, file, fileSource));
    const seen = new Set<string>();
    for (const c of cases) {
      if (seen.has(c.id)) throw new Error(file + ": duplicate case id " + c.id);
      seen.add(c.id);
    }
    result.push({ source: String(parsed.source ?? file), cases });
  }
  if (result.length === 0) {
    throw new Error("No case files found under " + CASES_DIR);
  }
  return result;
}

export async function loadCatalog(): Promise<TestCase[]> {
  const files = await loadCaseFiles();
  const all = files.flatMap((file) => file.cases);
  const ids = new Set<string>();
  for (const c of all) {
    if (ids.has(c.id)) throw new Error("duplicate case id across files: " + c.id);
    ids.add(c.id);
  }
  // Deduplicate exact-command duplicates across sources (the same command
  // appears in the corpus AND a red-team probe, or a generated case re-probes
  // a documented FP). Counting one command twice would inflate both the
  // escape and false-positive rates.
  const seenCommands = new Set<string>();
  const unique: TestCase[] = [];
  for (const c of all) {
    if (seenCommands.has(c.command)) continue;
    seenCommands.add(c.command);
    unique.push(c);
  }
  if (unique.length !== all.length) {
    console.warn("catalog: deduplicated " + (all.length - unique.length) + " exact-command duplicate(s)");
  }
  return unique;
}
