import { EXAMPLE_PROMPTS, type ExampleOutcome } from "../lib/exampleCommands";

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

export function ExamplePrompts({ onPick }: { onPick: (prompt: string) => void }) {
  return (
    <div className="example-groups">
      {order.map((outcome) => (
        <div key={outcome} className={"example-group severity-" + outcomeSeverity[outcome]}>
          <span className="example-group-label">{outcomeLabel[outcome]}</span>
          <div className="example-group-items">
            {EXAMPLE_PROMPTS.filter((item) => item.outcome === outcome).map((item) => (
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
    </div>
  );
}
