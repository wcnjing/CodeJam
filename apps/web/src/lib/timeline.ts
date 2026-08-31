import type {
  AgentRun,
  ApprovalRequest,
  CapabilityRequest,
  NetworkDenial,
  PolicyDecision,
} from "../types";
import { explainRule, type Severity } from "./ruleExplanations";

export type TimelineSeverity = Severity | "success" | "neutral";
export type TimelineKind = "run" | "policy" | "approval" | "network";

export interface TimelineEvent {
  id: string;
  at: string;
  kind: TimelineKind;
  severity: TimelineSeverity;
  title: string;
  detail?: string;
  command?: string;
  meta?: string;
  /**
   * The capability set the decision was made on.
   *
   * Carried because the timeline REPLACED the flat policy list, and that list
   * rendered these. "NETWORK_EGRESS -> attacker.example, via network-tool" is
   * what the engine actually decided on; the rule id is only the label it
   * happens to file under. Dropping it in the move would have quietly narrowed
   * the audit trail while the UI claimed to consolidate it.
   */
  capabilities?: CapabilityRequest[];
}

function truncate(text: string, max = 140): string {
  return text.length > max ? text.slice(0, max - 1) + "…" : text;
}

/**
 * Merges Run outcomes, PolicyDecisions, and ApprovalRequests into one feed,
 * MOST RECENT FIRST.
 *
 * Newest-first is the right default for an operator watching a live Agent — the
 * thing that just happened is the thing being reacted to. The order is named
 * here, and in the UI copy, because an earlier version of both said
 * "chronological" while sorting the other way. A blocked/held/terminated Run does not get its own
 * marker entry here — the policy or approval event for the same moment
 * already carries the detail, and duplicating it would just be noise. Run
 * entries only cover outcomes the other two streams don't explain:
 * completed, failed, cancelled.
 */
export function buildAuditTimeline(
  runs: AgentRun[],
  policyEvents: PolicyDecision[],
  approvals: ApprovalRequest[],
  networkEvents: NetworkDenial[] = [],
): TimelineEvent[] {
  const events: TimelineEvent[] = [];

  for (const run of runs) {
    if (run.status === "completed") {
      events.push({
        id: "run-" + run.id,
        at: run.completedAt ?? run.createdAt,
        kind: "run",
        severity: "success",
        title: "Run completed",
        detail: truncate(run.prompt),
      });
    } else if (run.status === "failed") {
      events.push({
        id: "run-" + run.id,
        at: run.completedAt ?? run.createdAt,
        kind: "run",
        severity: "neutral",
        title: "Run failed",
        detail: run.error ?? truncate(run.prompt),
      });
    } else if (run.status === "cancelled") {
      events.push({
        id: "run-" + run.id,
        at: run.completedAt ?? run.createdAt,
        kind: "run",
        severity: "neutral",
        title: "Run cancelled",
        detail: truncate(run.prompt),
      });
    }
  }

  for (const event of policyEvents) {
    const explanation = explainRule(event.rule);
    events.push({
      id: "policy-" + event.id,
      at: event.decidedAt,
      kind: "policy",
      severity: explanation.severity,
      title: explanation.label,
      detail: event.detail,
      command: event.command,
      meta: event.enforced ? "enforced" : "observed only (monitor mode)",
      capabilities: event.capabilities,
    });
  }

  // Network-layer denials. Deliberately their own `kind`, styled apart from a
  // policy decision, because they mean something different: the command ALREADY
  // RAN and the broker refused where it went, which is the classifier admitting
  // it did not see this one coming. Merging them into the policy stream would
  // read as "the policy caught it", which is the opposite of what happened.
  for (const event of networkEvents) {
    events.push({
      id: "network-" + event.id,
      at: event.observedAt,
      kind: "network",
      severity: "critical",
      title: "Network layer refused a destination",
      detail:
        event.reason +
        " — the command was not recognised by the policy layer, and the container had no route to " +
        event.host +
        ".",
      command: event.host + ":" + event.port,
      meta: "contained by the egress broker",
    });
  }

  // One marker per run whose evidence could NOT be read, so "no denials shown"
  // is never silently the same as "no denials happened".
  for (const run of runs) {
    if (run.networkEvidence !== "unavailable") continue;
    events.push({
      id: "network-unknown-" + run.id,
      at: run.completedAt ?? run.createdAt,
      kind: "network",
      severity: "review",
      title: "Network-layer evidence unavailable",
      detail:
        "The egress broker's log could not be read for this run. Containment still held — " +
        "the run had no route out except the broker — but whether it refused anything is UNKNOWN, " +
        "not none.",
      meta: "evidence collection failed; the run was unaffected",
    });
  }

  for (const approval of approvals) {
    const explanation = explainRule(approval.rule);
    const budgetContinuation = approval.rule === "step-budget-exceeded";
    if (approval.status === "pending") {
      events.push({
        id: "approval-" + approval.id,
        at: approval.requestedAt,
        kind: "approval",
        severity: "review",
        title: budgetContinuation
          ? "Awaiting command-allowance decision"
          : "Awaiting human approval",
        detail: approval.detail,
        command: approval.command,
      });
      continue;
    }
    events.push({
      id: "approval-" + approval.id,
      at: approval.resolvedAt ?? approval.requestedAt,
      kind: "approval",
      severity: approval.status === "approved" ? "success" : "critical",
      title:
        budgetContinuation
          ? approval.status === "approved"
            ? "Command allowance renewed"
            : "Task stopped at command allowance"
          : approval.status === "approved"
          ? explanation.label + " — approved and resumed"
          : explanation.label + " — denied",
      detail: approval.decisionReason ?? undefined,
      command: approval.command,
      meta: approval.resolvedBy
        ? "by " +
          approval.resolvedBy +
          // A migrated record's approver was typed in, not proven. The timeline
          // is read as evidence, so it must not show the two as equivalent.
          (approval.resolvedByAttribution === "self-asserted"
            ? " (self-asserted)"
            : "")
        : undefined,
    });
  }

  // Most recent first. See the doc comment: the ordering is a deliberate
  // choice, not an accident of Array.sort.
  return events.sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime());
}
