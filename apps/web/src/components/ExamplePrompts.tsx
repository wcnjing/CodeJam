import { EXAMPLE_PROMPTS, outcomeFor, type ExampleOutcome } from "../lib/exampleCommands";
import type { PolicyMode } from "../lib/ruleExplanations";

const outcomeLabel: Record<ExampleOutcome, string> = {
  allowed: "Sentinel allows this",
  held: "Sentinel holds this for approval",
  blocked: "Sentinel blocks this",
};

const outcomeSeverity: Record<ExampleOutcome, string> = {
  allowed: "success",
  held: "review",
  blocked: "critical",
};

const order: ExampleOutcome[] = ["allowed", "held", "blocked"];

/**
 * Grouped by what THIS deployment will do, not by what the default one does.
 * `mode` comes from /api/system; until it arrives the examples group by the
 * conservative reading (a denial is a block), never by an optimistic one.
 */
export function ExamplePrompts({
  onPick,
  mode,
}: {
  onPick: (prompt: string) => void;
  mode: PolicyMode | null;
}) {
  const grouped = order.map((outcome) => ({
    outcome,
    items: EXAMPLE_PROMPTS.filter((item) => outcomeFor(item, mode) === outcome),
  }));
  return (
    <div className="example-groups">
      {grouped
        .filter((group) => group.items.length > 0)
        .map((group) => (
          <div
            key={group.outcome}
            className={"example-group severity-" + outcomeSeverity[group.outcome]}
          >
            <span className="example-group-label">{outcomeLabel[group.outcome]}</span>
            <div className="example-group-items">
              {group.items.map((item) => (
                <button
                  key={item.prompt}
                  type="button"
                  className="example-card"
                  onClick={() => onPick(item.prompt)}
                >
                  <span className="example-card-prompt">{item.prompt}</span>
                  <span className="example-card-note">{item.note}</span>
                </button>
              ))}
            </div>
          </div>
        ))}
      {mode?.enforcement === "monitor" && (
        <p className="policy-note">
          This deployment is in monitor mode: every decision below is recorded as evidence
          and nothing is stopped, so all of these run.
        </p>
      )}
    </div>
  );
}
