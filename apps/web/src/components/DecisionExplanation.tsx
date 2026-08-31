import {
  describeConsequence,
  describeDisposition,
  explainRule,
  type PolicyMode,
  type RuntimeMode,
} from "../lib/ruleExplanations";

export function DecisionExplanation({
  rule,
  command,
  detail,
  hosts,
  mode = null,
  runtime = null,
}: {
  rule: string;
  command: string;
  detail: string;
  hosts?: string[];
  mode?: PolicyMode | null;
  /**
   * Which runtime is actually running. Without it the consequence copy asserts
   * the local-process answer -- "the Agent could reach any host" -- for a
   * container deployment where the broker would have refused anyway.
   */
  runtime?: RuntimeMode | null;
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
        <p>{describeConsequence(rule, runtime)}</p>
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
