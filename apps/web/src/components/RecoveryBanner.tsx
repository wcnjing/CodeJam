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
            "This was a resource limit, not a single denied command — earlier commands in this Run may have made real changes before the cutoff. Review the audit timeline above if you need to know exactly what ran.",
        }
      : cause === "denied"
        ? {
            heading: "Contained — you're clear to continue",
            container: "The held Run's container was already destroyed when it was denied.",
            asset:
              "Nothing on disk outside the denied command was touched. The workspace and any planted canary files are unchanged.",
          }
        : {
            heading: "Contained — you're clear to continue",
            container:
              "The Runtime container that ran the denied command has been destroyed. A fresh, clean container is created for the next Run.",
            asset:
              "Nothing on disk outside the denied command was touched. The workspace and any planted canary files are unchanged.",
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
