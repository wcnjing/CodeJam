export function RecoveryBanner({
  cause,
  workspacePath,
}: {
  cause: "blocked" | "terminated" | "denied";
  workspacePath: string;
}) {
  const containerNote =
    cause === "denied"
      ? "The held Run's container was already destroyed when it was denied."
      : "The Runtime container that ran the denied command has been destroyed.";
  return (
    <article className="recovery-banner" role="status">
      <div className="recovery-head">
        <span className="recovery-glyph">✓</span>
        <strong>Contained — you're clear to continue</strong>
      </div>
      <ul>
        <li>{containerNote} A fresh, clean container is created for the next Run.</li>
        <li>
          Nothing on disk outside the denied command was touched. The workspace and any
          planted canary files are unchanged.
        </li>
        <li>This Agent is ready for its next task — send a message below to continue.</li>
      </ul>
      <code>{workspacePath}</code>
    </article>
  );
}
