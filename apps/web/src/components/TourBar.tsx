import type { TourStep } from "../lib/evaluationTour";

export function TourBar({
  step,
  index,
  total,
  onNext,
  onPrev,
  onExit,
}: {
  step: TourStep;
  index: number;
  total: number;
  onNext: () => void;
  onPrev: () => void;
  onExit: () => void;
}) {
  return (
    <div className="tour-bar">
      <div className="tour-bar-copy">
        <div className="tour-bar-head">
          <span className="tour-step-count">
            {index + 1} / {total}
          </span>
          <strong>{step.title}</strong>
        </div>
        <p>{step.body}</p>
      </div>
      <div className="tour-bar-actions">
        <button className="button button-ghost" onClick={onPrev} disabled={index === 0}>
          Back
        </button>
        <button className="button button-primary" onClick={onNext}>
          {index === total - 1 ? "Done" : "Next"}
        </button>
        <button className="tour-exit" onClick={onExit} aria-label="Exit tour">
          ×
        </button>
      </div>
    </div>
  );
}
