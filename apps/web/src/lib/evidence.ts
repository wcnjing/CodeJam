import type { NetworkDenial, PolicyDecision } from "../types";

/**
 * Loads one agent's evidence, and refuses to apply a response that is no longer
 * the one being looked at.
 *
 * Extracted from `App.tsx` because the guard is the whole point of the function
 * and a guard nobody can test is a guard that comes back. Every other refresh
 * callback in that file checks `mountedRef.current && selectedIdRef.current ===
 * agentId` before setting state; the network-events fetch did not, so a slow
 * response for agent A could land after the operator had switched to agent B
 * and repopulate the timeline with A's records.
 *
 * That is worse than an ordinary UI race. This panel exists to show *per-agent*
 * network evidence — the destinations a run was refused — so the failure mode is
 * one agent's containment evidence appearing under another agent's name, which
 * is precisely the confusion the evidence is there to prevent.
 *
 * The server already scopes both endpoints to the requested agent, so this is a
 * display defect rather than a disclosure one. It is still a correctness bug in
 * the surface an operator reads to decide whether to trust the control.
 */
export interface EvidenceLoadDeps {
  fetchNetworkEvents: (agentId: string) => Promise<{ networkEvents: NetworkDenial[] }>;
  fetchPolicyEvents: (agentId: string) => Promise<{ policyEvents: PolicyDecision[] }>;
  /**
   * Whether a response for `agentId` is still wanted: the component is mounted
   * AND this agent is still the selected one. Read at APPLY time, never at
   * request time — the whole race is that the answer changes in between.
   */
  isCurrent: (agentId: string) => boolean;
  setNetworkEvents: (events: NetworkDenial[]) => void;
  setPolicyEvents: (events: PolicyDecision[]) => void;
}

export async function loadAgentEvidence(
  agentId: string,
  deps: EvidenceLoadDeps,
): Promise<void> {
  // A failure here must not blank the list into something that reads as "no
  // denials happened": leave the previous value in place instead. An absence of
  // evidence is not evidence of absence, and the run's own `networkEvidence`
  // field is what distinguishes "none" from "unknown".
  const network = await deps.fetchNetworkEvents(agentId).catch(() => null);
  if (network && deps.isCurrent(agentId)) {
    deps.setNetworkEvents(network.networkEvents);
  }

  const policy = await deps.fetchPolicyEvents(agentId);
  if (deps.isCurrent(agentId)) {
    deps.setPolicyEvents(policy.policyEvents);
  }
}
