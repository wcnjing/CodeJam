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
 * disabled by monitor mode. A resource limit is not a toggle.
 */
export class BudgetExceededError extends Error {
  constructor(
    public readonly limit: number,
    public readonly observed: number,
  ) {
    super(
      "Run terminated: step budget of " +
        limit +
        " commands exceeded (" +
        observed +
        " observed)",
    );
    this.name = "BudgetExceededError";
  }
}
