import { useState } from "react";
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
  /** Decision, plus whether the flagged hosts join the standing allowlist. */
  onResolve: (decision: "approve" | "deny", addToAllowlist: boolean) => void;
  mode?: PolicyMode | null;
}) {
  // A fresh approval remounts the card (keyed by id upstream), so the default
  // matches this hold: an egress hold offers to widen, and it is pre-checked —
  // approving a flagged host usually means "I trust this host". Unchecking it
  // approves for this run only.
  const [addToAllowlist, setAddToAllowlist] = useState(approval.hosts.length > 0);
  const canWiden = approval.hosts.length > 0;

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
        {canWiden && (
          <label className="approval-allowlist">
            <input
              type="checkbox"
              checked={addToAllowlist}
              onChange={(event) => setAddToAllowlist(event.target.checked)}
            />
            <span>
              Approve and add {approval.hosts.join(", ")} to the standing
              allowlist — future commands to it are allowed without approval.
            </span>
          </label>
        )}
      </div>
      <div className="approval-actions">
        <button
          className="button button-primary"
          disabled={busy || !principal || !reason.trim()}
          onClick={() => onResolve("approve", canWiden && addToAllowlist)}
        >
          {principal ? "Approve as " + principal.id : "Approve & resume"}
        </button>
        <button
          className="button button-danger"
          disabled={busy || !principal || !reason.trim()}
          onClick={() => onResolve("deny", false)}
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
        {principal && canWiden && !addToAllowlist && (
          <span className="policy-note">
            Approving without widening grants this one run only.
          </span>
        )}
      </div>
    </article>
  );
}

export function ResolvedApprovalCard({ approval }: { approval: ApprovalRequest }) {
  const widened = approval.allowlistWidened?.length ? approval.allowlistWidened : null;
  return (
    <article className="run-held" role="status">
      <strong>
        Approval {approval.status}
        {approval.resolvedBy ? " by " + approval.resolvedBy : ""}
        {approval.resolvedByAttribution === "self-asserted" && (
          // Predates credential-derived approvers: this name was typed into the
          // request, not proven. Saying so is the point of storing attribution.
          <span className="policy-note"> (self-asserted, not authenticated)</span>
        )}
      </strong>
      <span>
        {approval.status === "denied"
          ? "The request was denied; the held Run did not continue."
          : widened
            ? "The request was approved, resumed as a new Run, and its host(s) were added to the standing allowlist."
            : "The request was approved and resumed as a new Run."}
      </span>
      {widened && (
        <span className="policy-note">
          Added to the allowlist: {widened.join(", ")} — this was a permanent
          change, not a one-run grant.
        </span>
      )}
      {approval.decisionReason && <span className="policy-note">{approval.decisionReason}</span>}
    </article>
  );
}
