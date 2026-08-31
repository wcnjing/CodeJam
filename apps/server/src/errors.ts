import type { CapabilityRequest } from "./capabilities.js";

export class HttpError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export class RunCancelledError extends Error {
  constructor() {
    super("Run cancelled");
    this.name = "RunCancelledError";
  }
}

/**
 * Raised when the command policy denies a command observed mid-Run. Carries the
 * decision so `AgentService` can persist it as evidence rather than reducing the
 * outcome to an opaque failure message.
 */
export class PolicyViolationError extends Error {
  constructor(
    public readonly rule: string,
    public readonly command: string,
    public readonly detail: string,
    /** Hosts a human could grant a scoped exception for, if the rule is reviewable. */
    public readonly hosts: string[] = [],
    /** Capabilities the command requested, for the operator timeline. */
    public readonly capabilities: CapabilityRequest[] = [],
  ) {
    super("Blocked by command policy (" + rule + "): " + detail);
    this.name = "PolicyViolationError";
  }
}

/**
 * Raised when a run exceeds its step budget — too many shell commands in one
 * turn, the signature of a runaway loop or denial-of-wallet. Distinct from the
 * wall-clock timeout and output cap the Starter Kit already had: this is a
 * count the platform enforces, and unlike the command policy it is never
 * disabled by monitor mode. A resource limit is not a policy toggle.
 *
 * Whether the platform responds by holding the run for a human (the default:
 * `step-budget-exceeded` is in POLICY_REVIEW_RULES) or by terminating it
 * outright is AgentService's decision, made from this error's `limit` and
 * `observed`.
 */
export class BudgetExceededError extends Error {
  constructor(
    public readonly limit: number,
    public readonly observed: number,
  ) {
    super(
      "Run exceeded the step budget of " +
        limit +
        " commands (" +
        observed +
        " observed)",
    );
    this.name = "BudgetExceededError";
  }
}
