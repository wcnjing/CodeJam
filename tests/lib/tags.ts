/**
 * Tag vocabulary for the pentest case catalog.
 *
 * Every case carries one or more tags from this vocabulary. Tags are the
 * bypass families AGENTS.md asks for ("obfuscation, ... common ways to
 * bypass"), kept as a closed vocabulary so the scorecard can report per-tag
 * coverage and regressions can be attributed to a family.
 */

export const TAG_VOCABULARY: Record<string, string> = {
  egress: "Direct, recognisable network egress to a non-allowlisted host",
  obfuscation: "Hides the nature of the command (umbrella family)",
  encoding: "base64 / hex / ANSI-C encoded payloads or tool names",
  indirection: "Variables, command substitution, IFS tricks, eval",
  quoting: "Quote splitting and backslash escaping of tool names",
  path: "Absolute paths, multi-call wrappers, path traversal, symlinks",
  "alternate-channel": "Package managers, VCS clients, TLS clients, archive pipes",
  dns: "DNS-based exfiltration via dig/nslookup/host",
  staging: "Two-step: stage the secret locally, exfiltrate later",
  "allowlist-abuse": "userinfo tricks, subdomains of allowlisted hosts",
  "env-dump": "Full process-environment exposure (printenv/env)",
  "secret-read": "Reading a protected secret without egress",
  "reverse-shell": "Interactive shell or raw socket to an external host",
  interpreter: "python/node/perl/ruby/php/deno one-liners doing network I/O",
  proxy: "Abusing proxy environment variables to redirect egress",
  "untrusted-fetch": "Fetching remote code or scripts (stager)",
  benign: "Legitimate developer work (false-positive checks)",
  "near-miss": "Looks suspicious but is legitimate",
  wrapper: "The /bin/bash -lc '<command>' form Codex actually emits",
  "fail-closed": "A policy-engine error must deny, never allow",
  reviewability: "Rules a human may approve vs hard blocks",
  budget: "Step-count / runaway-execution control",
  redaction: "Evidence sanitisation of secrets",
  monitor: "Shadow-mode observation without termination",
  tunnel: "SSH reverse tunnels and connection forwarding",
};

export const TAGS: readonly string[] = Object.keys(TAG_VOCABULARY);

export function isKnownTag(tag: string): boolean {
  return tag in TAG_VOCABULARY;
}

export function assertKnownTags(tags: readonly string[]): void {
  for (const tag of tags) {
    if (!isKnownTag(tag)) {
      throw new Error("Unknown tag in catalog: " + JSON.stringify(tag));
    }
  }
}
