import type { EvaluationSummary } from "../types";

export interface TourStep {
  target: string;
  title: string;
  body: string;
}

const pct = (value: number) => (value * 100).toFixed(1) + "%";

/**
 * Step content pulls live numbers from the currently-measured summary, so
 * the tour never drifts from what the dashboard actually shows — same
 * principle as the dashboard itself being computed on demand from the
 * running policy engine, not a static screenshot.
 */
export function buildTourSteps(summary: EvaluationSummary): TourStep[] {
  const h = summary.headline;
  const escapedFamilies = summary.families.filter((f) => f.escaped > 0);
  return [
    {
      target: "hero",
      title: "Start here: the headline number",
      body:
        `Without Sentinel, the policy engine predicts every one of these ${summary.corpusSize} ` +
        `labelled attacks gets through — ${pct(h.baselineEscapeRate)}. With Sentinel active, ` +
        `that drops to ${pct(h.unsafeActionEscapeRate)}. This is a policy decision computed on ` +
        `a corpus we authored, not observed execution — real-world bypasses can still exist.`,
    },
    {
      target: "tile-attacks",
      title: "Attack block rate",
      body:
        `${h.attacks - h.escaped} of ${h.attacks} attack attempts are blocked outright ` +
        `(${pct(h.attackBlockRate)}). The residual isn't hidden — it's named two steps from now.`,
    },
    {
      target: "tile-secrets",
      title: "Secret leaks — the number that matters most",
      body:
        `${summary.secrets.leaks}/${summary.secrets.attacks} secret-exfiltration attempts got ` +
        `through, down from ${summary.secrets.baselineLeaks}/${summary.secrets.attacks} with no ` +
        `middleware. This is the one rule with no review path — read a protected secret and ` +
        `egress in the same command, and it's denied every time.`,
    },
    {
      target: "tile-fp",
      title: "False positives — is it too aggressive?",
      body:
        `${pct(summary.falsePositiveRate)} of ${summary.benign} legitimate tasks were incorrectly ` +
        `blocked. A guard that denies everything would also score a 0% escape rate — this number ` +
        `is what proves Sentinel isn't just refusing all traffic.`,
    },
    {
      target: "tile-latency",
      title: "The cost of checking",
      body:
        `About ${summary.latency.p95.toFixed(1)} microseconds of decision latency at the 95th ` +
        `percentile, per command. This check runs on every single command the Agent issues, not ` +
        `just the ones that look risky.`,
    },
    {
      target: "family",
      title: "Coverage by attack family",
      body:
        escapedFamilies.length > 0
          ? `Every family below is fully covered except the one marked ✗ — ` +
            `${escapedFamilies.map((f) => f.family).join(", ")}. That gap is documented, not ` +
            `swept under the rug.`
          : `Every attack family in the corpus is fully covered — no residual gaps this run.`,
    },
    {
      target: "classifier",
      title: "Classifier quality, blind-set honest",
      body:
        `"Blind-set recall" means these entries were written without reading the detection rules ` +
        `first — a check against the corpus being tuned to match its own answer key.`,
    },
    {
      target: "loop",
      title: "The full governance loop",
      body:
        `This is the shape of the whole system: every command is Intercepted, a Decision is made, ` +
        `risky ones are Contained or Held, a human can Approve, and the Agent Recovers to keep ` +
        `working. That loop — not a single filter — is what "Sentinel" means.`,
    },
  ];
}
