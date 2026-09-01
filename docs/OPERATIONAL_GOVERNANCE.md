# Operational governance: where this control stands

Operational guardrails are the ones that decide what happens *after* deployment
— not principles like "fairness," but controls over oversight, monitoring,
incidents, and authority. This document maps the Kill Switch honestly against
that lens, crediting real coverage and naming the gaps.

## Coverage

| Operational control | Status | Where |
| --- | --- | --- |
| **Agent authority limits** | **Strong.** Two independent layers: recognisable-egress denial (a command-text guard) plus, on `RUNTIME_PROVIDER=container`, structural default-deny networking — a per-run internal network with no outbound route and a per-run egress broker with a narrow allowlist. Also container + policy sandboxing, execution limits, tested prompt-injection and obfuscation resistance, and human approval before a reviewable action proceeds, which grants one host to one continuation run at both layers. `RUNTIME_PROVIDER=local-process` has the command guard only. See [Current Security Model](../README.md#current-security-model). | `command-policy.ts`, `network-isolation.ts`, `egress-broker.ts`, both runners, `resolveApproval` |
| **Meaningful human oversight** | **Implemented.** A held run gives a named human the exact command and reason, with authority to deny or grant a scoped exception. Override data (who, when, why) is recorded to detect rubber-stamping. | `ApprovalRequest`, `resolveApproval`, held-run UI |
| **Incident & near-miss handling** | **Strong.** Enforced denials are incidents; monitor-mode observations are recorded near-misses; evidence is redacted and preserved; rollback (container destroyed, workspace intact) is automatic. | `policyEvents` (`enforced` flag), monitor mode |
| **Explicit use boundaries** | Partial. Tool/host boundaries enforced at the Runtime; not yet re-triggered on environment change (see gaps). | allowlist, `.secrets/`, `AGENTS.md` |
| **Change-management triggers** | Partial. CI ratchets fail on policy-rule regressions. But the policy's correctness depends on the Runtime image's toolset (curl absent, node present) and the model — neither is a governed trigger. | `policy-eval.test.ts` |
| **Data & log governance** | Strong. Redaction is enforced before storage/display, and `policyEvents`/resolved `approvals` are pruned past `AUDIT_RETENTION_DAYS`. **Evidence does not outlive its Agent**: deleting an Agent removes its policy events *and* its network denials, in the same deletion path — see the retention policy below. Access controls beyond retention are still out of scope for the POC. | `redactCommand`, `JsonStore.prune`, `AgentService.deleteAgent` |
| **Post-deployment monitoring** | Partial. The substrate exists (persisted decisions, enforce-vs-monitor, override records); no drift/subgroup/rate dashboard yet. | `policyEvents`, `approvals` |
| **Appeal & redress** | Partial. The approval workflow is a structured reconsideration path for a held run. There is no path for an already-hard-blocked run. | `resolveApproval` |
| **Supply-chain, decommissioning, independent challenge** | Minor / out of scope. Pinned runtime image and `POLICY_ENFORCEMENT` off-switch exist; the rest is contractual or organizational, not a POC concern. | `Dockerfile.runtime`, config |

## The design choice that makes approval safe

Not every denial is reviewable. Only the egress rules — `network-egress-denied`
(a named tool reaching a host outside the allowlist) and
`network-egress-denied-implicit` (the same destination, with no recognised
tool naming it) — reach a legitimate need often enough (a package registry) to
be held for a human. `secret-exfiltration`, `protected-secret-access` and
`file-write-outside-workspace` are **always hard-denied and never subject to
approval**, so no operator can be socially-engineered or fatigued into waving
through the theft of a protected secret or a write past the sandbox boundary.
The reviewable set is `POLICY_REVIEW_RULES`, defaulting to egress only.

That third rule is why the container runner declares `/tmp` and `/var/tmp` as
write roots alongside `/workspace`: its container is `--rm` with two bind mounts,
so a scratch write there escapes nothing, and a rule with no appeal path must not
kill an ordinary run over `git diff > /tmp/patch.diff`. The host-process runner,
where `/tmp` is the real host `/tmp`, declares only the workspace path.

The granted exception is **scoped to the exact hosts named and consumed by a
single run** — proven live: after an approval let one task reach the npm
registry, the next task to the same registry was held again. Approval is never
a standing allowlist change **unless the approver explicitly asks for it**: the
approval card's "add to the allowlist" checkbox (and the Allowlist panel in the
UI) widen the store-backed override list, and such a decision is recorded on
the approval (`allowlistWidened`) so the audit trail says the approval was also
a permanent config change.

## Named, honest gaps

1. **No access control on the audit store.** `policyEvents` and `approvals` are
   now time-bounded (`AUDIT_RETENTION_DAYS`), but who can *read* the store once
   it's persisted is still ungoverned — this POC has no access-control layer.
2. **Ungoverned environment changes.** The policy assumes a specific runtime
   image and model. Adding `curl` to the image, or swapping the model, shifts the
   risk surface with nothing to re-trigger evaluation.
3. **Authenticated, not authorized.** "Approver" is now an authenticated
   principal resolved from the credential (`APP_PRINCIPALS`), so a decision can
   no longer be recorded under a name the decider simply typed. What remains is
   authorization: every principal may approve every held run, including one its
   own request caused, and the registry is static — no roles, no rotation, no
   segregation of duties.
4. **Hard-blocked runs have no appeal.** Only held (reviewable) runs can be
   reconsidered; a `secret-exfiltration`, `protected-secret-access` or
   `file-write-outside-workspace` block is final by design.
5. **The write boundary is enforced by tool name, not destination.**
   `file-write-outside-workspace` is a governance claim (no operator may approve
   it) resting on a detector that inspects only redirects and
   `cp`/`mv`/`tee`/`rm`/`mkdir`; `touch`, `dd`, `sed -i`, `install`, `ln`,
   `chmod` and interpreter writes are not seen. The authority limit is real; its
   coverage is first-pass. Recorded as unreduced residual likelihood on
   TM-AGENT-007 rather than as a solved control.

## Evidence retention policy

Two rules, stated rather than left to be inferred from the code.

**1. Age.** `policyEvents` and resolved `approvals` are pruned past
`AUDIT_RETENTION_DAYS` (default 90). A *pending* approval is live state — a held
run waiting on a human — not history, so it is exempt regardless of age and
becomes eligible only once resolved.

**2. Agent lifetime.** **Evidence does not outlive the Agent that produced it.**
Deleting an Agent removes its messages, runs, approvals, policy events and
network denials, in `AgentService.deleteAgent`.

The second rule is a decision, not an omission, and the argument for it is worth
recording because the opposite is defensible in other systems:

- A network denial names a **host and a run id**. Kept past the deletion of the
  Agent that produced it, it is a record nothing can resolve — an orphan, which
  is the thing an audit trail is supposed not to accumulate.
- Policy events already worked this way. The two kinds of evidence are
  deliberately parallel everywhere else in this design (stored apart, rendered
  apart, never merged). Divergent *lifetimes* would be a trap for anyone reading
  one list and reasoning about the other.
- Deleting an Agent is an operator action on their own workspace, not a
  compliance hold. This POC has no legal-hold concept, no per-Agent
  authorization, and no export path; retaining evidence past deletion would
  imply a guarantee none of those support.

**If you need evidence to survive deletion**, that is a different product: it
needs an export or archive step before the delete, a retention class that
deletion cannot override, and an answer for who may read records belonging to an
Agent that no longer exists. None of those exist here, and adding retention
without them would leave unreadable rows accumulating in a JSON blob.

**Known divergence, not yet closed.** Rule 1 does not apply to `networkEvents`:
they are pruned by rule 2 only. Age-based pruning covers `policyEvents` (via log
compaction) and resolved `approvals` (via `JsonStore.prune`), so a long-lived
Agent that keeps triggering broker denials accumulates them without bound. That
is the TM-OPS-001 shape again, on a newer record type, and it is tracked rather
than fixed here.
