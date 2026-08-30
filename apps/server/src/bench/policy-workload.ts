/**
 * The single definition of "one unit of policy work", shared by every harness
 * that reports a latency figure.
 *
 * The three timers this replaces each built their own workload inline, and the
 * differences were invisible at the call site: one used a filtered corpus, one
 * used the whole corpus, and all three re-derived the same context. Sharing the
 * workload is what makes their numbers comparable — a µs figure in the scorecard
 * now measures the same thing as a µs figure in the benchmark CLI.
 *
 * This is also the seam the `PolicyProbe` adapter will slot into when Person 1
 * lands the new engine: harnesses depend on this module, not on
 * `evaluateCommand` directly, so the migration is one file.
 */

import {
  evaluateCommand,
  policyContextFrom,
  type Actor,
  type PolicyContext,
} from "../command-policy.js";
import { CORPUS_WRITE_ROOTS, POLICY_CORPUS } from "../policy-corpus.js";

/**
 * The context every benchmark evaluates against. Pinned to one allowlisted host
 * so a measurement never depends on ambient configuration.
 */
export const BENCHMARK_CONTEXT: PolicyContext = policyContextFrom(
  "https://ark.cn-beijing.volces.com/api/v3",
  [],
  [],
  // The container runner's write roots. Without these every corpus redirect
  // would evaluate against an empty root list, which fails closed — so the
  // benchmark would time the FILE_WRITE denial path rather than the mix of
  // paths a real run takes.
  CORPUS_WRITE_ROOTS,
);

/**
 * The actor every benchmark evaluates as. Pinned for the same reason the
 * context is: a latency figure must not depend on which agent happened to run.
 */
export const BENCHMARK_ACTOR: Actor = { agentId: "benchmark", threadId: null };

/** Every command in the corpus, in corpus order. */
export const BENCHMARK_COMMANDS: readonly string[] = POLICY_CORPUS.map((entry) => entry.command);

/**
 * Build a zero-argument workload that evaluates one command per call, cycling
 * through `commands`.
 *
 * Cycling rather than repeating a single command matters: the rules short-circuit
 * at different depths, so hammering one input measures one branch and reports it
 * as the engine's latency. The cursor arithmetic is a compare and an increment,
 * well under the 100 ns clock tick, and is amortised away entirely when the
 * caller batches.
 */
export function policyWorkload(
  commands: readonly string[] = BENCHMARK_COMMANDS,
  context: PolicyContext = BENCHMARK_CONTEXT,
  actor: Actor = BENCHMARK_ACTOR,
): () => void {
  if (commands.length === 0) return () => {};
  let cursor = 0;
  return () => {
    evaluateCommand(actor, commands[cursor]!, context);
    cursor = cursor + 1 < commands.length ? cursor + 1 : 0;
  };
}
