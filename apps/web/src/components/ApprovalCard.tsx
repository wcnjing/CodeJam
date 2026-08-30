import type { ApprovalRequest, Principal } from "../types";
import { explainRule, type PolicyMode } from "../lib/ruleExplanations";
import { DecisionExplanation } from "./DecisionExplanation";

export function PendingApprovalCard({
  approval,
  principal,
  reason,
  onReasonChange,
  busy,
  onResolve,
  mode = null,
}: {
  approval: ApprovalRequest;
  /** Resolved from the credential. Null means this session cannot decide. */
  principal: Principal | null;
  reason: string;
  onReasonChange: (value: string) => void;
  busy: boolean;
  onResolve: (decision: "approve" | "deny") => void;
  mode?: PolicyMode | null;
}) {
  return (
    <article className="run-held" role="alert">
      <strong>Human approval required</strong>
      {/*
        Was hard-coded to "tried to reach a host outside the allowlist". Egress
        is no longer the only reviewable class — a write whose destination the
        command text cannot settle is reviewable too — so the specific reason
        comes from the rule and only the invariant part is stated here.
      */}
      <span>
        {explainRule(approval.rule).label}. The Run is held and its container
        destroyed. A person must approve or deny before the task can continue.
      </span>
      <DecisionExplanation
        rule={approval.rule}
        command={approval.command}
        detail={approval.detail}
        hosts={approval.hosts}
        mode={mode}
      />
      <div className="approval-controls">
        <label>
          Reason
          <input
            value={reason}
            onChange={(event) => onReasonChange(event.target.value)}
            placeholder="why you approve or deny"
          />
        </label>
      </div>
      <div className="approval-actions">
        <button
          className="button button-primary"
          disabled={busy || !principal || !reason.trim()}
          onClick={() => onResolve("approve")}
        >
          {principal ? "Approve as " + principal.id : "Approve & resume"}
        </button>
        <button
          className="button button-danger"
          disabled={busy || !principal || !reason.trim()}
          onClick={() => onResolve("deny")}
        >
          {principal ? "Deny as " + principal.id : "Deny"}
        </button>
        {!principal && (
          <span className="policy-note">
            Deciding requires an authenticated principal. Set APP_PRINCIPALS and unlock
            with that principal&apos;s token.
          </span>
        )}
        {principal && !reason.trim() && (
          <span className="policy-note">A reason is required to decide.</span>
        )}
      </div>
    </article>
  );
}

export function ResolvedApprovalCard({ approval }: { approval: ApprovalRequest }) {
  return (
    <article className="run-held" role="status">
      <strong>
        Approval {approval.status}
        {approval.resolvedBy ? " by " + approval.resolvedBy : ""}
      </strong>
      <span>
        {approval.status === "denied"
          ? "The request was denied; the held Run did not continue."
          : "The request was approved and resumed as a new Run."}
      </span>
      {approval.decisionReason && <span className="policy-note">{approval.decisionReason}</span>}
    </article>
  );
}
