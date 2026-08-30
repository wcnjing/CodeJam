import { EXAMPLE_COMMANDS } from "../lib/exampleCommands";
import { explainRule } from "../lib/ruleExplanations";

const capabilities = [
  {
    glyph: "＋",
    title: "Create coding Agents",
    body: "Spin up a Codex-backed Agent with its own persistent workspace and resumable session.",
  },
  {
    glyph: "↗",
    title: "Build in the Playground",
    body: "Chat with an Agent across multiple turns while it reads, writes, and runs commands in an isolated container.",
  },
  {
    glyph: "◆",
    title: "Review every decision",
    body: "When a command reaches outside the allowlist, the Run pauses — approve or deny it with a named reason.",
  },
  {
    glyph: "◈",
    title: "Measure the guard",
    body: "The Security Evaluation dashboard scores the live policy engine against an adversarial corpus, on demand.",
  },
];

export function WelcomePage({
  onOpenPlayground,
  onOpenEvaluation,
}: {
  onOpenPlayground: () => void;
  onOpenEvaluation: () => void;
}) {
  const blocked = EXAMPLE_COMMANDS.filter((item) => item.outcome === "blocked");
  const allowed = EXAMPLE_COMMANDS.filter((item) => item.outcome === "allowed");

  return (
    <div className="welcome-page">
      <section className="welcome-hero">
        <span className="eyebrow">Sentinel</span>
        <h1>Govern every action, not just every prompt.</h1>
        <p>
          AI Agents here run real shell commands in a real container. Sentinel intercepts
          every command mid-execution, checks it against policy, and stops or holds
          anything that crosses the line — before it becomes a Security Evaluation
          number instead of an incident.
        </p>
        <div className="welcome-cta">
          <button className="button button-primary" onClick={onOpenPlayground}>
            Open the Playground
          </button>
          <button className="button button-ghost" onClick={onOpenEvaluation}>
            See the Security Evaluation
          </button>
        </div>
      </section>

      <section className="welcome-capabilities">
        {capabilities.map((item) => (
          <div className="capability-card" key={item.title}>
            <span className="capability-glyph">{item.glyph}</span>
            <strong>{item.title}</strong>
            <p>{item.body}</p>
          </div>
        ))}
      </section>

      <section className="welcome-examples">
        <span className="eyebrow">What Sentinel actually catches</span>
        <h2>Same platform, two very different commands.</h2>
        <div className="example-columns">
          <div className="example-column severity-critical">
            <span className="example-column-label">Blocked</span>
            {blocked.map((item) => (
              <div className="example-command-card" key={item.command}>
                <code>{item.command}</code>
                <span className="policy-rule">
                  {item.rule ? explainRule(item.rule).label : "denied"}
                </span>
                <p>{item.note}</p>
              </div>
            ))}
          </div>
          <div className="example-column severity-success">
            <span className="example-column-label">Allowed</span>
            {allowed.map((item) => (
              <div className="example-command-card" key={item.command}>
                <code>{item.command}</code>
                <p>{item.note}</p>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
