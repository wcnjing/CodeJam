import { describeDisposition, explainRule, type PolicyMode } from "../lib/ruleExplanations";

export function DecisionExplanation({
  rule,
  command,
  detail,
  hosts,
  mode = null,
}: {
  rule: string;
  command: string;
  detail: string;
  hosts?: string[];
  mode?: PolicyMode | null;
}) {
  const explanation = explainRule(rule);
  return (
    <div className={"decision-explain severity-" + explanation.severity}>
      <div className="decision-explain-head">
        <span className="decision-glyph">{explanation.glyph}</span>
        <span className="policy-rule">{rule}</span>
      </div>
      <p className="decision-summary">{explanation.summary}</p>
      <p className="policy-note">{describeDisposition(rule, mode)}</p>
      <div className="decision-consequence">
        <span className="eyebrow">If this had not been caught</span>
        <p>{explanation.consequence}</p>
      </div>
      <code>{command}</code>
      <span className="policy-note">{detail}</span>
      {hosts && hosts.length > 0 && (
        <div className="decision-hosts">
          <span className="eyebrow">Destination</span>
          {hosts.map((host) => (
            <code key={host} className="decision-host">
              {host}
            </code>
          ))}
        </div>
      )}
    </div>
  );
}
