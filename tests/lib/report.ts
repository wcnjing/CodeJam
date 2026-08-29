/**
 * Report rendering + score persistence.
 *
 * Every suite run is written as JSON into tests/scores/ (the `scores` folder
 * AGENTS.md asks for; it lives under tests/ because that is the suite's only
 * writable area) and rendered to the console for humans.
 */

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { PerfReport, SuiteResult } from "./types.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const SCORES_DIR = path.resolve(HERE, "..", "scores");

export function pct(value: number): string {
  return (value * 100).toFixed(1) + "%";
}

export function renderSuite(result: SuiteResult): string {
  const lines: string[] = [];
  lines.push("");
  lines.push("── " + result.profileName + " (" + result.profileId + ") ──────────────");
  lines.push("  revision            " + result.revision);
  lines.push("  cases               " + result.totals.cases);
  lines.push("  passed / failed     " + result.totals.passed + " / " + result.totals.failed);
  lines.push("  attacks blocked     " + result.totals.maliciousBlocked + "/" + result.totals.malicious +
    "  (" + pct(result.totals.attackBlockRate) + ")");
  lines.push("  detection rate      " + pct(result.totals.detectionRate) +
    "   (" + result.totals.detectedMalicious + "/" + result.totals.malicious + " malicious commands detected)");
  lines.push("  escape rate         " + pct(result.totals.escapeRate) +
    "   (" + result.totals.maliciousEscaped + " malicious commands allowed)");
  lines.push("  false positives     " + pct(result.totals.falsePositiveRate) +
    "   (" + result.totals.benignBlocked + " benign commands blocked)");
  const tags = Object.entries(result.byTag).sort(([a], [b]) => a.localeCompare(b));
  if (tags.length > 0) {
    lines.push("  by tag:");
    for (const [tag, score] of tags) {
      lines.push(
        "    " + tag.padEnd(18) + pct(score.rate) + "   (" + score.passed + "/" + score.total + ")",
      );
    }
  }
  return lines.join("\n");
}

export function renderPerf(report: PerfReport): string {
  const lines: string[] = ["", "── Operational cost ──────────────────────────────"];
  for (const sample of report.samples) {
    lines.push(
      "  " + sample.metric.padEnd(40) +
        " mean " + sample.meanMicroseconds.toFixed(2).padStart(8) + " us" +
        "  p95 " + sample.p95Microseconds.toFixed(2).padStart(8) + " us" +
        "  " + Math.round(sample.opsPerSecond).toLocaleString("en-US").padStart(10) + " ops/s",
    );
    if (sample.byLength) {
      for (const [bucket, value] of Object.entries(sample.byLength)) {
        lines.push(
          "      " + bucket.padEnd(22) + value.meanMicroseconds.toFixed(2).padStart(8) + " us mean",
        );
      }
    }
  }
  return lines.join("\n");
}

export async function saveScore(name: string, payload: SuiteResult | PerfReport): Promise<string> {
  await mkdir(SCORES_DIR, { recursive: true });
  const file = path.join(SCORES_DIR, name + ".json");
  await writeFile(file, JSON.stringify(payload, null, 2), "utf8");
  return file;
}
