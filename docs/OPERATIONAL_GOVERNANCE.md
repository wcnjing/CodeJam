# Operational governance: where this control stands

Operational guardrails are the ones that decide what happens *after* deployment
— not principles like "fairness," but controls over oversight, monitoring,
incidents, and authority. This document maps the Kill Switch honestly against
that lens, crediting real coverage and naming the gaps.

## Coverage

| Operational control | Status | Where |
| --- | --- | --- |
| **Agent authority limits** | **Strong.** Recognisable-egress denial (a command-text guard, not a network allowlist), scoped allowlist for known destinations, container + policy sandboxing, execution limits, tested prompt-injection and obfuscation resistance, and — now — human approval before a reviewable action proceeds. | `command-policy.ts`, both runners, `resolveApproval` |
| **Meaningful human oversight** | **Implemented.** A held run gives a named human the exact command and reason, with authority to deny or grant a scoped exception. Override data (who, when, why) is recorded to detect rubber-stamping. | `ApprovalRequest`, `resolveApproval`, held-run UI |
| **Incident & near-miss handling** | **Strong.** Enforced denials are incidents; monitor-mode observations are recorded near-misses; evidence is redacted and preserved; rollback (container destroyed, workspace intact) is automatic. | `policyEvents` (`enforced` flag), monitor mode |
| **Explicit use boundaries** | Partial. Tool/host boundaries enforced at the Runtime; not yet re-triggered on environment change (see gaps). | allowlist, `.secrets/`, `AGENTS.md` |
| **Change-management triggers** | Partial. CI ratchets fail on policy-rule regressions. But the policy's correctness depends on the Runtime image's toolset (curl absent, node present) and the model — neither is a governed trigger. | `policy-eval.test.ts` |
| **Data & log governance** | Strong. Redaction is enforced before storage/display, and `policyEvents`/resolved `approvals` are now pruned past `AUDIT_RETENTION_DAYS` on every store write. Access/deletion controls beyond retention are still out of scope for the POC. | `redactCommand`, `JsonStore.prune` |
| **Post-deployment monitoring** | Partial. The substrate exists (persisted decisions, enforce-vs-monitor, override records); no drift/subgroup/rate dashboard yet. | `policyEvents`, `approvals` |
| **Appeal & redress** | Partial. The approval workflow is a structured reconsideration path for a held run. There is no path for an already-hard-blocked run. | `resolveApproval` |
| **Supply-chain, decommissioning, independent challenge** | Minor / out of scope. Pinned runtime image and `POLICY_ENFORCEMENT` off-switch exist; the rest is contractual or organizational, not a POC concern. | `Dockerfile.runtime`, config |

## The design choice that makes approval safe

Not every denial is reviewable. Only the egress rules — `network-egress-denied`
(a named tool reaching a host outside the allowlist) and
`network-egress-denied-implicit` (the same destination, with no recognised
tool naming it) — reach a legitimate need often enough (a package registry) to
be held for a human. `secret-exfiltration` and `protected-secret-access` are
**always hard-denied and never subject to approval**, so no operator can be
socially-engineered or fatigued into waving through the theft of a protected
secret. The reviewable set is `POLICY_REVIEW_RULES`, defaulting to egress only.

The granted exception is **scoped to the exact hosts named and consumed by a
single run** — proven live: after an approval let one task reach the npm
registry, the next task to the same registry was held again. Approval is never
a standing allowlist change.

## Named, honest gaps

1. **No access control on the audit store.** `policyEvents` and `approvals` are
   now time-bounded (`AUDIT_RETENTION_DAYS`), but who can *read* the store once
   it's persisted is still ungoverned — this POC has no access-control layer.
2. **Ungoverned environment changes.** The policy assumes a specific runtime
   image and model. Adding `curl` to the image, or swapping the model, shifts the
   risk surface with nothing to re-trigger evaluation.
3. **Identity is a label.** "Approver" is a free-text name, not an authenticated
   principal — this POC has no identity system. Real segregation of duties would
   plug an identity provider in exactly here (the "Bouncer" track this project
   did not take).
4. **Hard-blocked runs have no appeal.** Only held (reviewable) runs can be
   reconsidered; a `secret-exfiltration` block is final by design.
