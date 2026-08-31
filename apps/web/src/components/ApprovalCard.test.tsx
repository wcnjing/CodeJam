import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { ApprovalRequest } from "../types";
import { PendingApprovalCard } from "./ApprovalCard";

const budgetRequest: ApprovalRequest = {
  id: "budget-1",
  agentId: "agent-1",
  runId: "run-1",
  prompt: "complete the task",
  rule: "step-budget-exceeded",
  command: "(51 commands; limit 50)",
  detail: "The command allowance was reached.",
  hosts: [],
  status: "pending",
  requestedAt: "2026-09-01T00:00:00.000Z",
  resolvedBy: null,
  resolvedByAttribution: null,
  decisionReason: null,
  resolvedAt: null,
  continuationRunId: null,
};

describe("budget continuation card", () => {
  it("offers Continue and Stop without requiring an approval reason", () => {
    const html = renderToStaticMarkup(
      <PendingApprovalCard
        approval={budgetRequest}
        principal={null}
        reason=""
        onReasonChange={() => undefined}
        busy={false}
        onResolve={() => undefined}
      />,
    );

    expect(html).toContain("Command allowance reached");
    expect(html).toContain(">Continue<");
    expect(html).toContain(">Stop<");
    expect(html).not.toContain("Reason");
    expect(html).not.toContain("authenticated principal");
    expect(html).not.toContain("disabled");
  });
});
