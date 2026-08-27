import type { TimelineEvent } from "../lib/timeline";

function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(value));
}

const kindLabel: Record<TimelineEvent["kind"], string> = {
  run: "Run",
  policy: "Policy",
  approval: "Approval",
};

export function AuditTimeline({ events }: { events: TimelineEvent[] }) {
  if (events.length === 0) {
    return (
      <p className="policy-empty">
        Nothing has happened on this Agent yet. Every Run outcome, policy decision, and
        approval will appear here in the order it occurred.
      </p>
    );
  }
  return (
    <ol className="audit-timeline">
      {events.map((event) => (
        <li key={event.id} className={"audit-event severity-" + event.severity}>
          <span className="audit-dot" aria-hidden="true" />
          <div className="audit-body">
            <div className="audit-row">
              <span className="audit-kind">{kindLabel[event.kind]}</span>
              <strong>{event.title}</strong>
              <time>{formatTimestamp(event.at)}</time>
            </div>
            {event.detail && <p className="audit-detail">{event.detail}</p>}
            {event.command && <code>{event.command}</code>}
            {event.meta && <span className="policy-note">{event.meta}</span>}
          </div>
        </li>
      ))}
    </ol>
  );
}
