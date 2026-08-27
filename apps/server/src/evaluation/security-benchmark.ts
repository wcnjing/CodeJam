/**
 * Side-effect security benchmark.
 *
 * policy-eval.ts measures the classifier (did the rule fire?). This measures the
 * thing that actually matters: **did a prohibited side effect escape?** Every
 * attack carries a ground-truth family and effect; an attack "escapes" when the
 * policy ALLOWS it, at which point its declared effect would occur. The headline
 * number is the policy-predicted escape rate, not detection accuracy.
 *
 * Honesty notes:
 *  - This runs at the command-decision layer. Whether a byte physically leaves
 *    the container is proven separately by the live mock-collector test (zero
 *    requests) and the runner integration tests. This benchmark measures the
 *    enforcement invariant deterministically and in CI.
 *  - Attacks are reused from POLICY_CORPUS, so this is not an independent attack
 *    set; policy-eval.ts reports the blind-set figure for that. The value here
 *    is the escape framing and the baseline-vs-protected comparison.
 *  - The ground-truth effect comes from the corpus label, NOT from re-running the
 *    policy, so the measurement cannot be circular. The one documented residual
 *    (a fully base64-encoded command) is ground-truth malicious and is ALLOWED
 *    by the policy, so it correctly shows up here as an escape rather than being
 *    hidden.
 */

import { evaluateCommand, policyContextFrom } from "../middleware/command-policy.js";
import {
  EVASION_CATEGORIES,
  POLICY_CORPUS,
  type CorpusEntry,
} from "./policy-corpus.js";

export type Decision = "ALLOW" | "DENY";
export type Family =
  | "secret-extraction"
  | "network-exfil"
  | "reverse-shell"
  | "interpreter-egress"
  | "obfuscated-egress"
  | "benign";

const CONTEXT = policyContextFrom("https://ark.cn-beijing.volces.com/api/v3");

/** Ground-truth family for a corpus category. Independent of the policy rules. */
function familyOf(entry: CorpusEntry): Family {
  if (entry.label === "benign") return "benign";
  const c = entry.category;
  if (c === "secret-read" || c === "rt-indirect-read") return "secret-extraction";
  if (c === "reverse-shell") return "reverse-shell";
  if (c === "interpreter-egress") return "interpreter-egress";
  if (EVASION_CATEGORIES.has(c) || c.startsWith("evasion") || c.startsWith("rt-"))
    return "obfuscated-egress";
  return "network-exfil";
}

/** Attacks that expose a protected secret, for the dedicated secret-leak metric. */
function isSecretChannel(entry: CorpusEntry): boolean {
  return (
    entry.label === "malicious" &&
    (familyOf(entry) === "secret-extraction" ||
      /\.secrets?\b|ARK_API_KEY|id_rsa|\.aws\/cred|customer-db-url/.test(entry.command))
  );
}

export interface CaseResult {
  id: string;
  family: Family;
  malicious: boolean;
  decision: Decision;
  /** True when a malicious command was permitted and its effect would occur. */
  escaped: boolean;
  /** True when a benign command was wrongly denied. */
  falsePositive: boolean;
  secretChannel: boolean;
}

export interface BenchmarkResult {
  mode: "protected" | "baseline";
  cases: CaseResult[];
  attacks: number;
  blocked: number;
  escaped: number;
  attackBlockRate: number;
  unsafeActionEscapeRate: number;
  benign: number;
  benignBlocked: number;
  falsePositiveRate: number;
  secretAttacks: number;
  secretLeaks: number;
  byFamily: { family: Family; attacks: number; escaped: number }[];
}

/**
 * @param mode "baseline" allows everything (no middleware); "protected" applies
 * the command policy. Running both is the before/after experiment.
 */
export function runBenchmark(
  mode: "protected" | "baseline",
  corpus: CorpusEntry[] = POLICY_CORPUS,
): BenchmarkResult {
  const cases: CaseResult[] = [];
  const familyTotals = new Map<Family, { attacks: number; escaped: number }>();

  corpus.forEach((entry, index) => {
    const decision: Decision =
      mode === "baseline" ? "ALLOW" : evaluateCommand(entry.command, CONTEXT) ? "DENY" : "ALLOW";
    const malicious = entry.label === "malicious";
    const family = familyOf(entry);
    const escaped = malicious && decision === "ALLOW";
    const falsePositive = !malicious && decision === "DENY";
    const secretChannel = isSecretChannel(entry);

    cases.push({
      id: entry.category + "-" + index,
      family,
      malicious,
      decision,
      escaped,
      falsePositive,
      secretChannel,
    });

    if (malicious) {
      const bucket = familyTotals.get(family) ?? { attacks: 0, escaped: 0 };
      bucket.attacks += 1;
      if (escaped) bucket.escaped += 1;
      familyTotals.set(family, bucket);
    }
  });

  const attacks = cases.filter((c) => c.malicious).length;
  const escaped = cases.filter((c) => c.escaped).length;
  const blocked = attacks - escaped;
  const benign = cases.filter((c) => !c.malicious).length;
  const benignBlocked = cases.filter((c) => c.falsePositive).length;
  const secretAttacks = cases.filter((c) => c.secretChannel).length;
  const secretLeaks = cases.filter((c) => c.secretChannel && c.escaped).length;

  return {
    mode,
    cases,
    attacks,
    blocked,
    escaped,
    attackBlockRate: attacks === 0 ? 1 : blocked / attacks,
    unsafeActionEscapeRate: attacks === 0 ? 0 : escaped / attacks,
    benign,
    benignBlocked,
    falsePositiveRate: benign === 0 ? 0 : benignBlocked / benign,
    secretAttacks,
    secretLeaks,
    byFamily: [...familyTotals.entries()]
      .map(([family, v]) => ({ family, attacks: v.attacks, escaped: v.escaped }))
      .sort((a, b) => a.family.localeCompare(b.family)),
  };
}
