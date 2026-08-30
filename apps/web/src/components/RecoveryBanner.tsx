/**
 * What the platform can honestly tell an operator after containment.
 *
 * The first draft of this banner said "Nothing on disk outside the denied
 * command was touched. The workspace and any planted canary files are
 * unchanged." The platform does not check that and cannot promise it:
 * enforcement is interception DURING execution, so a command that completes
 * faster than the container teardown may finish. That is recorded as a known
 * limitation in the README and the threat model, and a reassurance in the UI
 * that contradicts the threat model is worse than no reassurance — it is the
 * one place an operator is most likely to believe it.
 *
 * What IS verified, and is all that is claimed here: the container is gone, no
 * further command from that Run ran, the decision is recorded, and the Agent is
 * usable again.
 */
export function RecoveryBanner({
  cause,
  workspacePath,
}: {
  cause: "blocked" | "terminated" | "denied";
  workspacePath: string;
}) {
  const copy =
    cause === "terminated"
      ? {
          heading: "Contained — you're clear to continue",
          container:
            "The Runtime container was stopped once the Run exceeded its step budget, and a fresh container is created for the next Run.",
          asset:
            "This was a resource limit, not a single denied command — earlier commands in this Run ran normally and may have made real changes. The audit timeline above lists what the Runtime observed.",
        }
      : cause === "denied"
        ? {
            heading: "Contained — you're clear to continue",
            container: "The held Run's container was already destroyed when it was denied.",
            asset:
              "No further command from that Run ran. The denied command itself was intercepted mid-execution, so whether it completed a partial effect before teardown is not something the platform can confirm — check the workspace if it matters.",
          }
        : {
            heading: "Contained — you're clear to continue",
            container:
              "The Runtime container that ran the denied command has been destroyed. A fresh, clean container is created for the next Run.",
            asset:
              "No further command from that Run ran. The denied command itself was intercepted mid-execution, so whether it completed a partial effect before teardown is not something the platform can confirm — check the workspace if it matters.",
          };
  return (
    <article className="recovery-banner" role="status">
      <div className="recovery-head">
        <span className="recovery-glyph">✓</span>
        <strong>{copy.heading}</strong>
      </div>
      <ul>
        <li>{copy.container}</li>
        <li>{copy.asset}</li>
        <li>This Agent is ready for its next task — send a message below to continue.</li>
      </ul>
      <code>{workspacePath}</code>
    </article>
  );
}
