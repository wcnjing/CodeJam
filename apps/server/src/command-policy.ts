/**
 * Policy: capabilities -> a decision.
 *
 * The pipeline is deliberately three layers —
 *
 *   command text -> shell-parse.ts -> capabilities.ts -> these rules
 *
 * — so that a rule reads as a statement about what an actor may do, not as a
 * pattern over shell syntax. Adding a governed action type means teaching the
 * capability layer to emit it; the rules below do not change.
 */

import {
  extractCapabilities,
  isTextualUrlOnly,
  type Capability,
  type CapabilityRequest,
  type PolicyContext,
} from "./capabilities.js";

export type { PolicyContext, Capability, CapabilityRequest };

/** Who issued the command — the run/agent identity, not the human approver. */
export interface Actor {
  agentId: string;
  threadId: string | null;
}

/** One capability request, reshaped as the resource half of a decision tuple. */
export interface Resource {
  kind: "host" | "secret" | "path";
  value: string;
  trusted: boolean;
  via: CapabilityRequest["via"];
}

/** Everything a decision needs beyond the action+resource: run-scoped facts. */
export interface DecisionContext extends PolicyContext {
  /** A URL that is being written as text rather than fetched. Per-command, not per-resource. */
  textualOnly: boolean;
}

export type Decision =
  | { effect: "ALLOW" }
  | {
      effect: "DENY";
      rule: string;
      detail: string;
      reviewable: boolean;
      hosts?: string[];
    };

/**
 * A policy scoped to exactly one capability, reading as a statement about the
 * tuple: "this action on this resource, in this context, is denied because...".
 *
 * `detail`/`hosts` take every resource that matched `when` in one command, not
 * just the one passed to `decide()` — real orchestration (Task 3) aggregates
 * across all of a command's resources for the matching policy before building
 * the final violation, so "Command contacts non-allowlisted host(s): a, b, c"
 * keeps listing every host, not just the first.
 */
export interface Policy {
  id: string;
  statement: string;
  action: Capability;
  reviewable: boolean;
  when: (resource: Resource, context: DecisionContext, actor: Actor) => boolean;
  detail: (resources: Resource[], context: DecisionContext) => string;
  /** Present only when a human could grant a scoped exception (the egress rules). */
  hosts?: (resources: Resource[]) => string[];
}

/**
 * Decide one action on one resource. Pure: no extraction, no aggregation across
 * a command's other resources — see `Policy`'s doc comment for where the
 * aggregation happens.
 */
export function decide(
  actor: Actor,
  action: Capability,
  resource: Resource,
  context: DecisionContext,
  policies: Policy[],
): Decision {
  for (const policy of policies) {
    if (policy.action !== action) continue;
    if (!policy.when(resource, context, actor)) continue;
    return {
      effect: "DENY",
      rule: policy.id,
      detail: policy.detail([resource], context),
      reviewable: policy.reviewable,
      ...(policy.hosts ? { hosts: policy.hosts([resource]) } : {}),
    };
  }
  return { effect: "ALLOW" };
}

export interface PolicyViolation {
  rule: string;
  detail: string;
  /** Non-allowlisted hosts a human could grant a scoped exception for. */
  hosts?: string[];
  /**
   * The capabilities the command requested. Carried on the decision so evidence
   * and the operator timeline can name what was attempted — "NETWORK_EGRESS to
   * attacker.example" — instead of quoting the rule that happened to match.
   */
  capabilities?: CapabilityRequest[];
}

/** Maps a capability request onto the `kind` a Resource carries. */
function toResource(request: CapabilityRequest): Resource {
  const kind: Resource["kind"] =
    request.capability === "NETWORK_EGRESS"
      ? "host"
      : request.capability === "SECRET_READ"
        ? "secret"
        : "path";
  return { kind, value: request.resource, trusted: request.trusted, via: request.via };
}

/**
 * Cross-capability rules don't fit a single actor+action+resource tuple — they
 * govern the *set* of actions an actor takes in one command. Evaluated before
 * the per-tuple POLICY_RULES pass (see the module's CombinationPolicy pass
 * below), so secret-exfiltration keeps the top priority it has today.
 */
export interface CombinationPolicy {
  id: string;
  statement: string;
  reviewable: boolean;
  when: (requests: CapabilityRequest[], context: DecisionContext) => boolean;
  detail: (requests: CapabilityRequest[]) => string;
}

const COMBINATION_POLICIES: CombinationPolicy[] = [
  {
    id: "secret-exfiltration",
    statement: "An actor holding SECRET_READ may not also exercise NETWORK_EGRESS.",
    reviewable: false,
    when: (requests) =>
      requests.some((r) => r.capability === "SECRET_READ") &&
      requests.some(
        (r) =>
          r.capability === "NETWORK_EGRESS" && (r.via === "network-tool" || r.via === "interpreter"),
      ),
    detail: (requests) => {
      const secret = requests.find((r) => r.capability === "SECRET_READ")?.resource ?? "";
      return "Command combines network egress with access to " + secret + ".";
    },
  },
];

/**
 * Per-capability policies. Order is significant: the first policy with any
 * matching resource decides the whole command, so a hard denial must be
 * ordered ahead of a reviewable one it could otherwise be shadowed by.
 * `file-write-outside-workspace` therefore leads: a command that both writes
 * outside the sandbox and contacts a non-allowlisted host must NOT report the
 * reviewable egress rule, because an approved command is rerun verbatim
 * without re-evaluation — the operator would be waving through a sandbox
 * escape they were never shown.
 *
 * `network-egress-denied` / `network-egress-denied-implicit` stay mutually
 * exclusive per resource via `via` — a resource with `via ===
 * "destination-only"` can only match the implicit rule, never the named-tool
 * rule, which is what keeps an obfuscated destination reporting the correct id.
 */
const POLICY_RULES: Policy[] = [
  {
    id: "file-write-outside-workspace",
    statement: "FILE_WRITE is permitted only inside the run's workspace.",
    action: "FILE_WRITE",
    reviewable: false,
    when: (resource) => !resource.trusted,
    detail: (resources) =>
      "Command writes outside the workspace: " + resources.map((r) => r.value).join(", ") + ".",
  },
  {
    id: "network-egress-denied",
    statement: "NETWORK_EGRESS is permitted only to destinations on the run's allowlist.",
    action: "NETWORK_EGRESS",
    reviewable: true,
    when: (resource) => !resource.trusted && resource.via !== "destination-only",
    detail: (resources) =>
      "Command contacts non-allowlisted host(s): " +
      resources.map((r) => r.value).join(", ") +
      ".",
    hosts: (resources) => resources.map((r) => r.value),
  },
  {
    id: "network-egress-denied-implicit",
    statement:
      "A destination with no recognised network tool is still NETWORK_EGRESS: " +
      "an obfuscated command can hide its binary but not where it connects.",
    action: "NETWORK_EGRESS",
    reviewable: true,
    when: (resource, context) =>
      !resource.trusted && resource.via === "destination-only" && !context.textualOnly,
    detail: (resources) =>
      "Command references non-allowlisted host(s) without a recognised " +
      "network tool, which is how an obfuscated command hides its binary: " +
      resources.map((r) => r.value).join(", ") +
      ".",
    hosts: (resources) => resources.map((r) => r.value),
  },
  {
    id: "protected-secret-access",
    statement: "SECRET_READ on protected material is denied on its own.",
    action: "SECRET_READ",
    reviewable: false,
    when: () => true,
    detail: (resources) => "Command reads " + resources[0]?.value + ".",
  },
];

/** True only for rules a human is permitted to approve. */
export function isReviewableRule(rule: string): boolean {
  return REVIEWABLE_RULES.includes(rule);
}

/**
 * The ONLY rules a human may ever be asked to approve. Derived from the policy
 * table's own `reviewable` flag rather than hand-maintained separately, so the
 * two can never drift apart. This stays a code-level invariant, not a config
 * value: a non-allowlisted egress can be a legitimate need (a package
 * registry), so it is reviewable — but reading or exfiltrating a protected
 * secret, or writing outside the sandbox, is never something an operator can
 * wave through, no matter what `POLICY_REVIEW_RULES` is set to. Config is
 * intersected with this set and rejected if it names anything outside it (see
 * config.ts).
 */
export const REVIEWABLE_RULES: readonly string[] = [
  ...POLICY_RULES.filter((policy) => policy.reviewable).map((policy) => policy.id),
  ...COMBINATION_POLICIES.filter((policy) => policy.reviewable).map((policy) => policy.id),
];

/**
 * Decide whether a command may run.
 *
 * Returns the first matching rule, or null when every capability the command
 * requests is permitted in this context. Combination policies are checked
 * first (secret-exfiltration's priority today), then per-tuple policies in
 * POLICY_RULES order — for each, every resource in the command that matches
 * is aggregated into one violation, not just the first (see Policy's doc
 * comment).
 */
export function evaluateCommand(
  actor: Actor,
  command: string,
  context: PolicyContext,
): PolicyViolation | null {
  if (!command.trim()) return null;

  const requests = extractCapabilities(command, context);
  const decisionContext: DecisionContext = { ...context, textualOnly: isTextualUrlOnly(command) };

  for (const combination of COMBINATION_POLICIES) {
    if (!combination.when(requests, decisionContext)) continue;
    return {
      rule: combination.id,
      detail: combination.detail(requests),
      capabilities: requests,
    };
  }

  for (const policy of POLICY_RULES) {
    const matching = requests
      .filter((request) => request.capability === policy.action)
      .map(toResource)
      .filter((resource) => policy.when(resource, decisionContext, actor));
    if (matching.length === 0) continue;
    const hosts = policy.hosts?.(matching);
    return {
      rule: policy.id,
      detail: policy.detail(matching, decisionContext),
      ...(hosts && hosts.length > 0 ? { hosts } : {}),
      capabilities: requests,
    };
  }
  return null;
}

/**
 * The capabilities a command requests, for operator display and evidence.
 * Exposes the same facts the decision was made on, so a timeline can say
 * "requested NETWORK_EGRESS to attacker.example" rather than quoting a regex.
 */
export function describeCapabilities(
  command: string,
  context: PolicyContext,
): CapabilityRequest[] {
  return command.trim() ? extractCapabilities(command, context) : [];
}

/**
 * The invariants the rule set enforces, for the threat model and docs. Covers
 * both passes evaluateCommand runs, in the order it runs them: a combination
 * rule such as secret-exfiltration is as much a documented invariant as a
 * per-tuple one, and listing only POLICY_RULES would silently drop it.
 */
export function policyStatements(): { rule: string; statement: string }[] {
  return [...COMBINATION_POLICIES, ...POLICY_RULES].map((r) => ({
    rule: r.id,
    statement: r.statement,
  }));
}

export function allowedHostsFrom(arkBaseUrl: string): string[] {
  try {
    return [new URL(arkBaseUrl).hostname.toLowerCase()];
  } catch {
    return [];
  }
}

const REDACTED = "***REDACTED***";

// Credentials embedded in a URL authority, e.g. postgres://user:pw@host.
//
// The user/password segments are length-bounded (real credentials are far
// shorter) so a `\b` restart inside a long adversarial non-whitespace run
// costs O(1) instead of re-scanning to the end of the string — the same
// quadratic-blowup shape HIGH_ENTROPY_RUN had, on the same evidence-building
// path, just needing no real "://" or "@" in the input to trigger it.

const URL_CREDENTIALS = /(\b[a-z][a-z0-9+.-]{0,15}:\/\/[^\s:/@"']{1,255}:)[^\s@"']{1,255}(@)/gi;

// Long opaque strings: API keys, tokens, base64 blobs. Deliberately conservative
// so ordinary arguments, paths and hashes-in-filenames are left readable.
//
// A single greedy run of the allowed charset, checked in one linear pass —
// not the lookahead-per-`\b`-restart-point form this replaced, which let a
// long non-whitespace argument (no real secret needed) force a quadratic scan
// on the exact path that builds security evidence for a denial.

const HIGH_ENTROPY_RUN = /[A-Za-z0-9_+/=-]+/g;

function isHighEntropyRun(run: string): boolean {
  if (run.length < 28) return false;
  let hasLetter = false;
  let hasDigit = false;
  for (let i = 0; i < run.length && !(hasLetter && hasDigit); i += 1) {
    const code = run.charCodeAt(i);
    if ((code >= 65 && code <= 90) || (code >= 97 && code <= 122)) hasLetter = true;
    else if (code >= 48 && code <= 57) hasDigit = true;
  }
  return hasLetter && hasDigit;
}

/**
 * Removes secret material from a command before it is recorded as evidence.
 *
 * A policy decision is stored, served over the API and rendered in the browser.
 * Without this, a command that inlined a resolved credential would leak it
 * through the very audit trail meant to protect it. Redaction is applied where
 * the violation is constructed, so the raw text never leaves the Runtime.
 */

export function redactCommand(command: string, secretValues: readonly string[] = []): string {
  let redacted = command;
  for (const secret of secretValues) {
    // Only mask values substantial enough to be a real credential; masking a
    // short or empty value would blank out unrelated text.
    if (secret && secret.length >= 8) {
      redacted = redacted.split(secret).join(REDACTED);
    }
  }
  redacted = redacted.replace(URL_CREDENTIALS, "$1" + REDACTED + "$2");
  redacted = redacted.replace(HIGH_ENTROPY_RUN, (run) => (isHighEntropyRun(run) ? REDACTED : run));
  return redacted;
}

export interface DetectedViolation extends PolicyViolation {
  command: string;
}

/**
 * Evaluates one command, failing closed: if evaluation throws, the command is
 * denied, not allowed. A safety control that crashes must not become a bypass.
 * `evaluate` is injectable so the fail-closed path is testable.
 */

export function guardedEvaluate(
  actor: Actor,
  command: string,
  context: PolicyContext,
  evaluate: (actor: Actor, command: string, context: PolicyContext) => PolicyViolation | null = evaluateCommand,
): PolicyViolation | null {
  try {
    return evaluate(actor, command, context);
  } catch {
    return {
      rule: "policy-error",
      detail: "Policy evaluation failed; failing closed and denying the command.",
    };
  }
}

/**
 * Evaluates commands observed since `startIndex` and returns EVERY denial in
 * order — not just the first. Returning all of them keeps monitor-mode evidence
 * complete when one streamed batch contains several violating commands.
 *
 * Both runners stream Codex events and need identical policy behaviour, so the
 * scan lives here rather than being duplicated per runner.
 */

export function scanCommands(
  actor: Actor,
  commands: readonly string[],
  startIndex: number,
  context: PolicyContext,
): DetectedViolation[] {
  const found: DetectedViolation[] = [];
  for (let index = startIndex; index < commands.length; index += 1) {
    const command = commands[index];
    if (!command) continue;
    const violation = guardedEvaluate(actor, command, context);
    if (violation) {
      found.push({ ...violation, command: redactCommand(command, context.secretValues) });
    }
  }
  return found;
}

/** Ark's own host is always reachable; operators may allow more via config. */
// Loopback is the container talking to itself (a local dev server the Agent
// spun up to test), not an exfiltration channel — the host-side collector lives
// on host.docker.internal, which is NOT loopback. Allowed by default and
// consistently, so `curl localhost:3000` and `curl http://localhost/health`
// behave the same. Obfuscated forms (decimal/IPv6 that happen to encode
// loopback) are still denied — no legitimate task writes `curl 2130706433`.

const LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "::1"];

export function policyContextFrom(
  arkBaseUrl: string,
  extraHosts: readonly string[] = [],
  secretValues: readonly string[] = [],
  workspaceRoot = "",
): PolicyContext {
  return {
    allowedHosts: [...allowedHostsFrom(arkBaseUrl), ...LOOPBACK_HOSTS, ...extraHosts],
    secretValues: [...secretValues],
    workspaceRoot,
  };
}