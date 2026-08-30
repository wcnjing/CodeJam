import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { risk, THREAT_REGISTER } from "./threat-model.js";

const here = path.dirname(fileURLToPath(import.meta.url));
// Tests live in src/__tests__/ since the source reorganisation; scan them for
// @covers tags. Fall back to this CLI's own directory when they are absent
// (e.g. a built dist, which excludes tests).
function testsDirectory(): string {
  const candidate = path.join(here, "..", "__tests__");
  try {
    readdirSync(candidate);
    return candidate;
  } catch {
    console.warn(
      "threat-model-cli: no " + candidate + " (this happens in a built dist, " +
        "which excludes tests). Falling back to " + here + " — mitigated threats " +
        "with no @covers tag in reach will report NO.",
    );
    return here;
  }
}
const testsDir = testsDirectory();
const covered = new Set<string>();
for (const file of readdirSync(testsDir)) {
  if (!file.endsWith(".test.ts")) continue;
  const text = readFileSync(path.join(testsDir, file), "utf8");
  for (const m of text.matchAll(/@covers\s+((?:TM-[A-Z]+-\d+\s*)+)/g)) {
    for (const id of m[1]!.trim().split(/\s+/)) covered.add(id);
  }
}

const band = (r: number) =>
  r >= 20 ? "CRIT" : r >= 15 ? "HIGH" : r >= 8 ? "MED " : "LOW ";

console.log("Threat register");
console.log("===============\n");
console.log(
  "  " +
    "ID".padEnd(14) +
    "STATUS".padEnd(11) +
    "INHERENT".padEnd(10) +
    "RESIDUAL".padEnd(10) +
    "VERIFIED",
);
for (const t of THREAT_REGISTER) {
  const ir = risk(t.inherent);
  const rr = risk(t.residual);
  const verified = t.status === "mitigated" ? (covered.has(t.id) ? "yes" : "NO") : "-";
  console.log(
    "  " +
      t.id.padEnd(14) +
      t.status.padEnd(11) +
      (ir + " " + band(ir)).padEnd(10) +
      (rr + " " + band(rr)).padEnd(10) +
      verified,
  );
}

const mitigated = THREAT_REGISTER.filter((t) => t.status === "mitigated");
const verified = mitigated.filter((t) => covered.has(t.id)).length;
const open = THREAT_REGISTER.filter((t) => t.status !== "mitigated");
console.log("\nVerified-control rate: " + verified + "/" + mitigated.length + " mitigated threats");
if (open.length) {
  console.log("Tracked open/accepted risks:");
  for (const t of open) console.log("  - " + t.id + " (" + t.status + "): " + t.title);
}
