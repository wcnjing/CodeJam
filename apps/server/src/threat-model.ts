/**
 * Threat register — as code, so it is type-checked and machine-verifiable.
 *
 * The discipline this encodes: a mitigated threat is only mitigated if a real
 * test proves its control. `threat-model.test.ts` enforces that every threat
 * marked `mitigated` is referenced by at least one `@covers <id>` tag in the
 * test sources, so a control that loses its test fails the build. A register
 * that cannot fail is documentation, not verification.
 *
 * Risk uses likelihood x impact on a 1..5 scale. Impact often stays high after
 * mitigation because the theoretical consequence is unchanged; controls reduce
 * probability and blast radius, not the worst case.
 */

export interface Control {
  id: string;
  description: string;
  /** The component that enforces it. */
  where: string;
}

export interface RiskScore {
  likelihood: number;
  impact: number;
}

export interface Threat {
  id: string;
  title: string;
  /** Methodology lenses this was found through. */
  methodology: string[];
  assets: string[];
  actor: string;
  trustBoundary: string;
  entryPoint: string;
  attackPath: string[];
  inherent: RiskScore;
  controls: Control[];
  residual: RiskScore;
  residualNote: string;
  owner: string;
  status: "mitigated" | "accepted" | "open";
  reviewTriggers: string[];
}

export const risk = (score: RiskScore): number => score.likelihood * score.impact;

export const THREAT_REGISTER: Threat[] = [
  {
    id: "TM-AGENT-001",
    title: "Indirect prompt injection causes an unauthorized tool action",
    methodology: ["STRIDE: Elevation of Privilege", "OWASP Agentic: Goal Hijacking"],
    assets: ["protected workspace data", "external network authority"],
    actor: "attacker controlling content the agent reads",
    trustBoundary: "agent reasoning -> deterministic command execution",
    entryPoint: "a file in the workspace (e.g. a vendored README)",
    attackPath: [
      "attacker plants an instruction inside a document the agent will read",
      "agent treats the document's data as an instruction",
      "agent proposes a consequential shell command",
      "command reaches the runtime",
    ],
    inherent: { likelihood: 4, impact: 5 },
    controls: [
      {
        id: "CTRL-POLICY-DENY",
        description: "Deterministic command policy denies exfiltration-shaped commands, independent of model output",
        where: "command-policy.ts, both runners",
      },
      {
        id: "CTRL-AUDIT",
        description: "Redacted policy decision recorded with run correlation",
        where: "agent-service.ts executeRun",
      },
    ],
    residual: { likelihood: 2, impact: 5 },
    residualNote:
      "Model refusal is a first layer but not depended on; the policy enforces regardless. A fully base64-encoded command evades text matching (see TM-AGENT-002).",
    owner: "runtime-security",
    status: "mitigated",
    reviewTriggers: ["new tool exposed to the agent", "model or provider change"],
  },
  {
    id: "TM-AGENT-002",
    title: "Secret exfiltration to a non-allowlisted network destination",
    methodology: ["STRIDE: Information Disclosure", "OWASP: SSRF / outbound exfiltration"],
    assets: ["ARK_API_KEY", "protected .secrets/ fixture"],
    actor: "malicious or injected task",
    trustBoundary: "runtime -> external resource",
    entryPoint: "a shell command executed in the run",
    attackPath: [
      "task reads a protected secret",
      "task sends it to an attacker-controlled host",
    ],
    inherent: { likelihood: 4, impact: 5 },
    controls: [
      {
        id: "CTRL-EGRESS-DENY",
        description: "Denies commands with a recognisable non-allowlisted destination (URL/host/interpreter/reverse-shell), any binary; NOT a network allowlist — implicit destinations are not caught",
        where: "command-policy.ts",
      },
      {
        id: "CTRL-SECRET-RULE",
        description: "Reading protected material combined with egress is a hard denial, never reviewable",
        where: "command-policy.ts, agent-service.ts",
      },
      {
        id: "CTRL-REDACT",
        description: "Credentials masked before evidence is stored or displayed",
        where: "command-policy.ts redactCommand",
      },
    ],
    residual: { likelihood: 2, impact: 5 },
    residualNote:
      "A fully-encoded command (eval base64) defeats text matching; only network-layer egress control closes it. Documented, not hidden.",
    owner: "runtime-security",
    status: "mitigated",
    reviewTriggers: ["allowlist widened", "runtime image gains a network tool"],
  },
  {
    id: "TM-AGENT-003",
    title: "Obfuscated command hides its tool name to evade the policy",
    methodology: ["Attack tree: egress via alternate tool/encoding", "Misuse case"],
    assets: ["external network authority"],
    actor: "adversary crafting the command, or a model that reaches for an unusual tool",
    trustBoundary: "agent reasoning -> deterministic command execution",
    entryPoint: "a shell command in the run",
    attackPath: [
      "command hides the binary (quotes, variables, interpreters, wrappers)",
      "or names the destination only",
    ],
    inherent: { likelihood: 3, impact: 5 },
    controls: [
      {
        id: "CTRL-DEST-BASED",
        description: "A non-allowlisted destination is egress regardless of which binary carries it; interpreter and wrapper forms covered",
        where: "command-policy.ts",
      },
    ],
    residual: { likelihood: 2, impact: 5 },
    residualNote:
      "red-team + external-review probes folded into the corpus; one residual (base64 eval). Corpus keeps every probe so fixes cannot regress.",
    owner: "runtime-security",
    status: "mitigated",
    reviewTriggers: ["new evasion class discovered"],
  },
  {
    id: "TM-AGENT-004",
    title: "Runaway execution / denial of wallet",
    methodology: ["STPA: unsafe control action", "OWASP: unbounded consumption"],
    assets: ["compute and model spend"],
    actor: "a looping or manipulated agent (no attacker required)",
    trustBoundary: "control plane -> runtime",
    entryPoint: "the command stream of a single run",
    attackPath: [
      "agent enters a loop or is steered to issue many commands",
      "commands accumulate unbounded within one turn",
    ],
    inherent: { likelihood: 3, impact: 4 },
    controls: [
      {
        id: "CTRL-STEP-BUDGET",
        description: "Platform-enforced step budget kills a run exceeding N commands; always on, not subject to monitor mode",
        where: "both runners, config POLICY_MAX_COMMANDS",
      },
    ],
    residual: { likelihood: 2, impact: 3 },
    residualNote:
      "A single expensive command within budget is not caught; token/cost budgets would complement this.",
    owner: "runtime-team",
    status: "mitigated",
    reviewTriggers: ["budget default changed", "new expensive tool added"],
  },
  {
    id: "TM-AGENT-005",
    title: "Consequential egress waved through without human oversight",
    methodology: ["Misuse case", "OWASP: excessive agency / approvals"],
    assets: ["external network authority"],
    actor: "an over-trusted agent reaching a plausibly-legitimate but unvetted host",
    trustBoundary: "human -> agent",
    entryPoint: "a denied egress that may be legitimate (e.g. a package registry)",
    attackPath: [
      "agent needs a host outside the allowlist",
      "without review it is either blocked (blocks real work) or allowed (blind trust)",
    ],
    inherent: { likelihood: 3, impact: 4 },
    controls: [
      {
        id: "CTRL-APPROVAL",
        description: "Reviewable egress holds the run for a named human; approval grants a run-scoped host grant (for the reviewed hosts, this run only); decision and reason recorded",
        where: "agent-service.ts resolveApproval",
      },
      {
        id: "CTRL-NO-SECRET-APPROVAL",
        description: "Secret-access rules are never reviewable; no human can approve exfiltration",
        where: "config POLICY_REVIEW_RULES default",
      },
    ],
    residual: { likelihood: 2, impact: 3 },
    residualNote:
      "Approver is a free-text label, not an authenticated principal (no identity system in this POC); automation bias is possible and override rates should be reviewed.",
    owner: "runtime-security",
    status: "mitigated",
    reviewTriggers: ["reviewable rule set changed", "identity provider added"],
  },
  {
    id: "TM-AGENT-006",
    title: "One agent's safety evidence leaks to another",
    methodology: ["STRIDE: Information Disclosure", "LINDDUN: Linking"],
    assets: ["policy decisions", "approval records"],
    actor: "a caller reading another agent's evidence",
    trustBoundary: "control plane data access",
    entryPoint: "the policy-events and approvals endpoints",
    attackPath: ["query one agent's evidence", "receive another agent's records"],
    inherent: { likelihood: 2, impact: 3 },
    controls: [
      {
        id: "CTRL-SCOPE",
        description: "Evidence and approvals filtered by agent id in the service layer",
        where: "agent-service.ts getPolicyEvents / listApprovals",
      },
    ],
    residual: { likelihood: 1, impact: 3 },
    residualNote: "Single-process JSON store; no cross-tenant isolation beyond ownership scoping.",
    owner: "runtime-team",
    status: "mitigated",
    reviewTriggers: ["multi-user identity added", "store backend changed"],
  },
  {
    id: "TM-AGENT-007",
    title: "Agent writes outside the sandboxed workspace",
    methodology: ["STRIDE: Tampering", "OWASP Agentic: Excessive Agency"],
    assets: ["host filesystem", "other agents' workspaces", "container writable surface"],
    actor: "a looping or manipulated agent reaching past its own workspace",
    trustBoundary: "agent execution -> filesystem writes",
    entryPoint: "any shell command with a write-shaped target (redirect, cp/mv/tee/rm/mkdir)",
    attackPath: [
      "agent (directly, or via injected instruction) issues a command whose write target resolves outside its mounted workspace",
      "the write lands on host-adjacent or another agent's storage the agent was never granted",
    ],
    inherent: { likelihood: 3, impact: 3 },
    controls: [
      {
        id: "CTRL-FILE-WRITE-DENY",
        description:
          "FILE_WRITE requests resolved against the write roots the runner declares (container: /workspace + the container-local /tmp, /var/tmp; host process: the workspace path only); any write outside them is hard-denied, never reviewable",
        where: "capabilities.ts extractCapabilities, command-policy.ts file-write-outside-workspace",
      },
    ],
    residual: { likelihood: 3, impact: 3 },
    residualNote:
      "This is NOT the egress rules' obfuscation limit; the gap is far more basic. Only shell redirects (>, >>, >|) and a five-tool list (cp, mv, tee, rm, mkdir) are inspected, so any other write-capable tool passes unseen — `touch /etc/x`, `dd of=/etc/x`, `sed -i s/a/b/ /etc/hosts`, `install -m 755 payload /usr/local/bin/x`, `ln -s`, `chmod 777 /etc/passwd`, and interpreter writes (python3 -c \"open('/etc/passwd','w')\") are all allowed today, verified by hand. That is tool-name matching, the exact pattern red-teaming already found inadequate for egress (POLICY_EVALUATION.md finding 10), which is why the egress rule was moved to destination matching. Likelihood is therefore NOT reduced below inherent: the rule stops the common redirect/copy shapes a looping agent produces, not an actor that picks a different binary. A destination-based FILE_WRITE model (resolve the target, not the tool) is the tracked follow-up.",
    owner: "runtime-team",
    status: "mitigated",
    reviewTriggers: [
      "a new write-shaped tool added to the runtime image",
      "before the write rule is claimed to be destination-based rather than tool-based",
    ],
  },
  {
    id: "TM-OPS-001",
    title: "Unbounded audit-log growth",
    methodology: ["LINDDUN: Non-compliance", "OWASP: secret leakage through logs"],
    assets: ["policy decisions", "approval records"],
    actor: "none (operational hazard)",
    trustBoundary: "safety/audit store",
    entryPoint: "every recorded decision",
    attackPath: [
      "decisions and approvals accumulate with no retention or access bound",
      "the audit store becomes a second sensitive datastore",
    ],
    inherent: { likelihood: 3, impact: 2 },
    controls: [
      {
        id: "CTRL-REDACT-ONLY",
        description: "Records are redacted before storage, so a leaked record carries no secret material",
        where: "command-policy.ts redactCommand",
      },
      {
        id: "CTRL-RETENTION-BOUND",
        description:
          "policyEvents and resolved approvals are pruned once older than AUDIT_RETENTION_DAYS on every store mutation. A still-pending approval is exempt regardless of age — it's live state, not history",
        where: "store.ts JsonStore.prune",
      },
    ],
    residual: { likelihood: 1, impact: 2 },
    residualNote:
      "Bounded, where it was previously OPEN. The cost of the unbounded case was measured before it was fixed: `npm run bench:store` showed recording one decision cost O(events already stored) - a fixed cost plus ~2.3 us per stored event, r-squared 0.9998, reaching ~11.7 ms at 5000 events against ~2.3 us for the policy decision itself - so unbounded growth was a live performance regression as well as an audit-surface risk. AUDIT_RETENTION_DAYS now caps how long records accumulate and redaction still bounds per-record exposure. The residual is a misconfiguration (retention set far too high) rather than unbounded growth, and the store-overhead harness remains the way to detect it.",
    owner: "runtime-team",
    status: "mitigated",
    reviewTriggers: ["before any non-POC deployment", "AUDIT_RETENTION_DAYS default changed"],
  },
];
