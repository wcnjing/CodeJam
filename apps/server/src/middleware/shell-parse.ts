/**
 * Shell command parsing: raw command text -> structured invocations and the
 * destinations they name.
 *
 * This layer knows nothing about policy. It answers only "what would actually
 * run, and what does it talk to?" — deliberately separate from the decision,
 * because the ceiling of a text-matching control is reached here, not in the
 * rules. Everything policy-facing is derived from these structures rather than
 * from scanning the command string for suggestive substrings.
 */

import { isIP } from "node:net";

export const NETWORK_TOOL_NAMES = new Set([
  "curl", "wget", "nc", "ncat", "netcat", "telnet", "ssh", "scp", "sftp",
  "rsync", "ftp", "socat", "openssl", "aria2c", "httpie", "http", "xh",
  "dig", "nslookup", "host", "ping", "ping6", "lwp-request",
]);

// Strip a `/bin/bash -lc '...'` / `sh -c "..."` wrapper to reach the real command
// Codex ran. Everything below reasons about the inner command.

export function unwrapShell(command: string): string {
  let inner = command;
  for (let depth = 0; depth < 8; depth += 1) {
    const match = inner.match(
      /^\s*(?:\S*\/)?(?:ba|z|da)?sh\s+-\S*c\s+(['"])([\s\S]*)\1\s*$/i,
    );
    if (!match) break;
    inner = match[2]!;
  }
  return inner;
}

// A command substitution runs its body as a command of its own, so `$(curl h)`
// and `` `nc h 4444` `` must be analysed rather than read as an argument to
// whatever encloses them. The body is lifted out for separate analysis and the
// hole is filled with a token that can never parse as a host, so the enclosing
// command keeps its shape without inventing a destination.

const SUBSTITUTION_PLACEHOLDER = "$SUBSTITUTION";

function splitSubstitutions(command: string): { outer: string; inner: string[] } {
  const inner: string[] = [];
  let outer = "";
  let quote: "'" | '"' | null = null;
  let escaped = false;
  for (let index = 0; index < command.length; index += 1) {
    const char = command[index]!;
    if (escaped) {
      outer += char;
      escaped = false;
      continue;
    }
    if (char === "\\" && quote !== "'") {
      outer += char;
      escaped = true;
      continue;
    }
    if (char === "'" || char === '"') {
      if (quote === char) quote = null;
      else if (!quote) quote = char;
      outer += char;
      continue;
    }
    // Single quotes suppress substitution; double quotes do not.
    if (quote === "'") {
      outer += char;
      continue;
    }
    const dollarParen = char === "$" && command[index + 1] === "(";
    if (dollarParen || char === "`") {
      const opened = dollarParen ? index + 1 : index;
      const closed = dollarParen
        ? matchingParen(command, opened)
        : command.indexOf("`", opened + 1);
      if (closed > opened) {
        inner.push(command.slice(opened + 1, closed));
        outer += SUBSTITUTION_PLACEHOLDER;
        index = closed;
        continue;
      }
    }
    outer += char;
  }
  return { outer, inner };
}

function matchingParen(text: string, open: number): number {
  let depth = 0;
  for (let index = open; index < text.length; index += 1) {
    if (text[index] === "(") depth += 1;
    else if (text[index] === ")") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

// Split on unquoted shell control operators. This is intentionally lightweight,
// but unlike String.split it does not turn a `|` inside a quoted Node/Python
// program into a fictitious command.

function commandSegments(command: string): string[] {
  const segments: string[] = [];
  let current = "";
  let quote: "'" | '"' | null = null;
  let escaped = false;
  for (let index = 0; index < command.length; index += 1) {
    const char = command[index]!;
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === "\\" && quote !== "'") {
      current += char;
      escaped = true;
      continue;
    }
    if (char === "'" || char === '"') {
      if (quote === char) quote = null;
      else if (!quote) quote = char;
      current += char;
      continue;
    }
    if (!quote && (char === ";" || char === "|" || char === "&" || char === "\n")) {
      if (current.trim()) segments.push(current.trim());
      current = "";
      if ((char === "|" || char === "&") && command[index + 1] === char) index += 1;
      continue;
    }
    current += char;
  }
  if (current.trim()) segments.push(current.trim());
  return segments;
}

function baseName(token: string): string {
  const structural = token
    .replace(/^\$?\(+/, "")
    .replace(/^[!{]+/, "")
    .replace(/[)}]+$/, "");
  return (structural.split("/").pop() ?? structural).toLowerCase();
}

/** Tokenize one already-isolated command segment, removing shell quotes. */

export function shellWords(segment: string): string[] {
  const words: string[] = [];
  let current = "";
  let quote: "'" | '"' | null = null;
  let escaped = false;
  const flush = () => {
    if (current) words.push(current);
    current = "";
  };
  for (const char of segment) {
    if (escaped) {
      current += char;
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
      else current += char;
      continue;
    }
    if (!quote && /\s/.test(char)) {
      flush();
      continue;
    }
    current += char;
  }
  if (escaped) current += "\\";
  flush();
  return words;
}

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

const SIMPLE_WRAPPERS = new Set(["exec", "nohup"]);

const SHELL_PREFIXES = new Set(["then", "do", "else", "elif", "time", "builtin"]);

const SUDO_VALUE_OPTIONS = new Set(["-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt", "-C", "--chdir"]);

/**
 * Resolve the command actually invoked after assignments and common wrappers.
 * `unwrapEnv` lets network parsing see `env FOO=bar curl ...`, while environment
 * policy can inspect `env` itself.
 */

export function invocationFromSegment(
  segment: string,
  unwrapEnv: boolean,
): { tool: string; args: string[] } | null {
  const words = shellWords(segment);
  let index = 0;
  while (ASSIGNMENT.test(words[index] ?? "")) index += 1;

  while (index < words.length) {
    const tool = baseName(words[index]!);
    if (SHELL_PREFIXES.has(tool)) {
      index += 1;
      if (tool === "time") {
        while (words[index]?.startsWith("-")) index += 1;
      }
      continue;
    }
    if (tool === "command") {
      // `command -v env` / `command -V env` inspect a name; they do not invoke
      // it. Plain `command env` and `command -- env` are execution wrappers.
      if (words[index + 1] === "-v" || words[index + 1] === "-V") {
        return { tool, args: words.slice(index + 1) };
      }
      index += 1;
      if (words[index] === "--") index += 1;
      continue;
    }
    if (SIMPLE_WRAPPERS.has(tool)) {
      index += 1;
      while (words[index]?.startsWith("-") && words[index] !== "--") index += 1;
      if (words[index] === "--") index += 1;
      continue;
    }
    if (tool === "sudo") {
      index += 1;
      while (index < words.length && words[index]!.startsWith("-")) {
        const option = words[index]!;
        index += 1;
        if (!option.includes("=") && SUDO_VALUE_OPTIONS.has(option)) index += 1;
      }
      continue;
    }
    if (tool === "timeout") {
      index += 1;
      while (words[index]?.startsWith("-")) index += 1;
      if (index < words.length) index += 1; // duration
      continue;
    }
    if (tool === "busybox") {
      index += 1;
      continue;
    }
    if (tool === "env" && unwrapEnv) {
      index += 1;
      while (index < words.length) {
        const word = words[index]!;
        if (word === "--") {
          index += 1;
          break;
        }
        if (word === "-S" || word === "--split-string") {
          const split = shellWords(words[index + 1] ?? "");
          words.splice(index, 2, ...split);
          continue;
        }
        if (word.startsWith("--split-string=")) {
          const split = shellWords(word.slice("--split-string=".length));
          words.splice(index, 1, ...split);
          continue;
        }
        if (word === "-u" || word === "--unset" || word === "-C" || word === "--chdir") {
          index += 2;
          continue;
        }
        if (word.startsWith("-") || ASSIGNMENT.test(word)) {
          index += 1;
          continue;
        }
        break;
      }
      continue;
    }
    return { tool, args: words.slice(index + 1) };
  }
  return null;
}

export const SHELL_NAMES = new Set(["sh", "bash", "zsh", "dash", "ksh"]);

const FIND_EXEC_OPTIONS = new Set(["-exec", "-execdir", "-ok", "-okdir"]);
// Tools that take a destination and then a command to run at that destination.

const REMOTE_COMMAND_TOOLS = new Set(["ssh"]);
// Tools whose first host-shaped positional is the destination; anything after
// it is a remote command or a port, not a second hop.

const ONE_DESTINATION_TOOLS = new Set([
  "ssh", "sftp", "telnet", "ftp", "ping", "ping6", "nc", "ncat",
  "netcat", "dig", "nslookup", "host",
]);

/**
 * Commands carried as *arguments* to another command, which still execute.
 * Without this, only the leading binary of a segment is ever resolved, so
 * `find . -exec curl h \;` and `ssh host nc h 4444` name no network tool.
 */

function nestedCommands(segment: string): string[] {
  const invocation = invocationFromSegment(segment, true);
  if (!invocation) return [];
  const { tool, args } = invocation;

  // `sh -c '...'` anywhere, not just as the whole command.
  if (SHELL_NAMES.has(tool)) {
    for (let index = 0; index < args.length; index += 1) {
      const argument = args[index]!;
      if (argument.startsWith("-") && /c/.test(argument.slice(1)) && args[index + 1]) {
        return [args[index + 1]!];
      }
    }
    return [];
  }

  if (tool === "find") {
    const nested: string[] = [];
    for (let index = 0; index < args.length; index += 1) {
      if (!FIND_EXEC_OPTIONS.has(args[index]!)) continue;
      const body: string[] = [];
      index += 1;
      while (index < args.length && args[index] !== ";" && args[index] !== "+") {
        body.push(args[index]!);
        index += 1;
      }
      if (body.length > 0) nested.push(body.join(" "));
    }
    return nested;
  }

  if (tool === "xargs") {
    const valueOptions = new Set(["-I", "-i", "-L", "-n", "-P", "-s", "-d", "-E", "-a", "--replace", "--max-args", "--max-procs", "--delimiter", "--arg-file"]);
    let index = 0;
    while (index < args.length) {
      const argument = args[index]!;
      if (!argument.startsWith("-")) break;
      if (argument.includes("=")) {
        index += 1;
        continue;
      }
      index += 1;
      if (valueOptions.has(argument)) index += 1;
    }
    const body = args.slice(index).join(" ");
    return body ? [body] : [];
  }

  // `ssh host <remote command>` runs the tail on the far side; its own
  // destinations matter just as much as the hop it travels through.
  if (REMOTE_COMMAND_TOOLS.has(tool)) {
    const positionals = positionalArgs(tool, args);
    const destination = positionals.findIndex(
      (argument) => hostFromToken(argument) !== null,
    );
    const remote = destination < 0 ? [] : positionals.slice(destination + 1);
    return remote.length > 0 ? [remote.join(" ")] : [];
  }

  return [];
}

/**
 * Every command that would actually run, including those nested inside command
 * substitution, `sh -c` bodies, and exec-style wrappers.
 */

export function executableSegments(command: string, depth = 0): string[] {
  if (depth > 6) return [];
  const { outer, inner } = splitSubstitutions(command);
  const segments: string[] = [];
  for (const segment of commandSegments(outer)) {
    segments.push(segment);
    for (const nested of nestedCommands(segment)) {
      segments.push(...executableSegments(nested, depth + 1));
    }
  }
  for (const body of inner) {
    segments.push(...executableSegments(body, depth + 1));
  }
  return segments;
}

// Extract a destination from an argument that is already known to occupy a
// network-tool destination position. Context is the important part here:
// `curl react.dev`, `curl evil`, and `ssh user@process.com` are destinations,
// while the same strings in `echo` or a commit message are just text.

export function hostFromToken(token: string): string | null {
  let t = token
    .replace(/^['"`(]+/, "")
    .replace(/['"`),;}]+$/, "");
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) {
    try {
      return new URL(t).hostname.replace(/^\[|\]$/g, "").toLowerCase();
    } catch {
      t = t.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
    }
  }
  t = t.replace(/^.*@/, "");
  const v6 = t.match(/^\[([^\]]+)\]/);
  if (v6 && isIP(v6[1]!.replace(/%.+$/, "")) === 6) {
    return v6[1]!.toLowerCase();
  }
  t = t.split("/")[0]!;
  if (isIP(t.replace(/%.+$/, ""))) return t.toLowerCase();

  // A single colon is a URL port or scp path separator. Multiple colons are a
  // raw IPv6 literal and were handled above.
  if ((t.match(/:/g) ?? []).length === 1) t = t.slice(0, t.indexOf(":"));
  if (!t || !/^[a-z0-9.-]+$/i.test(t)) return null;

  // WHATWG URL parsing canonicalises decimal/octal/hex and shortened IPv4,
  // closing forms such as 2130706433 and 127.1 without hand-rolled arithmetic.
  try {
    const canonical = new URL("http://" + t).hostname.toLowerCase();
    if (canonical && /^[a-z0-9.-]+$/i.test(canonical)) {
      // Non-canonical numeric spellings are useful SSRF/allowlist evasions.
      // Report the literal rather than silently turning 2130706433 into the
      // allowlisted 127.0.0.1.
      if (/^(?:\d|0x)/i.test(t) && canonical !== t.toLowerCase()) {
        return t.toLowerCase();
      }
      return canonical;
    }
  } catch {
    // Fall through to null for malformed labels.
  }
  return null;
}

export function networkToolInvocations(command: string): { tool: string; args: string[] }[] {
  return executableSegments(command)
    .map((segment) => invocationFromSegment(segment, true))
    .filter(
      (invocation): invocation is { tool: string; args: string[] } =>
        invocation !== null && NETWORK_TOOL_NAMES.has(invocation.tool),
    );
}

export function networkToolSegments(command: string): string[] {
  return networkToolInvocations(command).map(
    (invocation) => invocation.tool + " " + invocation.args.join(" "),
  );
}

const TOOL_VALUE_OPTIONS: Record<string, ReadonlySet<string>> = {
  curl: new Set([
    "-o", "--output", "-d", "--data", "--data-ascii", "--data-binary",
    "--data-raw", "--data-urlencode", "-H", "--header", "-A",
    "--user-agent", "-e", "--referer", "-F", "--form", "-T",
    "--upload-file", "-u", "--user", "-x", "--proxy", "--preproxy",
    "--url", "-X", "--request", "-w", "--write-out", "--cacert",
    "--capath", "--cert", "--key", "--resolve", "--connect-to",
    "--unix-socket", "--max-time", "--connect-timeout", "--retry",
    "--retry-delay", "--limit-rate", "-b", "--cookie", "-c",
    "--cookie-jar", "-K", "--config", "--netrc-file", "--trace",
    "--trace-ascii", "-D", "--dump-header", "--output-dir",
  ]),
  wget: new Set([
    "-O", "--output-document", "-o", "--output-file", "-P",
    "--directory-prefix", "--header", "--post-data", "--post-file",
    "--user-agent", "--referer", "--timeout", "--tries", "--wait",
    "--quota", "--bind-address", "--ca-certificate", "--certificate",
    "--private-key", "-e", "--execute", "-i", "--input-file",
  ]),
  aria2c: new Set([
    "-o", "--out", "-d", "--dir", "--header", "--user-agent",
    "--referer", "--timeout", "--connect-timeout", "--load-cookies",
    "--save-cookies", "--all-proxy", "--http-proxy", "--https-proxy",
    "--ftp-proxy",
  ]),
  ssh: new Set([
    "-b", "-c", "-D", "-E", "-F", "-i", "-J", "-L", "-l", "-m",
    "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w",
  ]),
  sftp: new Set([
    "-B", "-b", "-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P",
    "-R", "-S",
  ]),
  scp: new Set([
    "-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-S", "-X",
  ]),
  rsync: new Set(["-e", "--rsh", "--rsync-path", "--password-file"]),
  ping: new Set([
    "-c", "-i", "-I", "-l", "-M", "-m", "-p", "-Q", "-s", "-t",
    "-W", "-w",
  ]),
  ping6: new Set([
    "-c", "-i", "-I", "-l", "-M", "-m", "-p", "-Q", "-s", "-t",
    "-W", "-w",
  ]),
  nc: new Set(["-e", "-i", "-p", "-q", "-s", "-w", "-x", "-X"]),
  ncat: new Set([
    "-e", "--exec", "-i", "--idle-timeout", "-p", "--source-port",
    "-s", "--source", "-w", "--wait", "--proxy", "--proxy-type",
  ]),
  netcat: new Set(["-e", "-i", "-p", "-q", "-s", "-w", "-x", "-X"]),
};

const TOOL_HOST_OPTIONS: Record<string, ReadonlySet<string>> = {
  curl: new Set(["-x", "--proxy", "--preproxy", "--url"]),
  aria2c: new Set([
    "--all-proxy", "--http-proxy", "--https-proxy", "--ftp-proxy",
  ]),
  ssh: new Set(["-J", "-W"]),
  sftp: new Set(["-J"]),
  scp: new Set(["-J"]),
  nc: new Set(["-x"]),
  ncat: new Set(["--proxy"]),
  netcat: new Set(["-x"]),
};

function hostOptionValues(tool: string, args: string[]): string[] {
  const values: string[] = [];
  const options = TOOL_HOST_OPTIONS[tool] ?? new Set<string>();
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index]!;
    if (argument.startsWith("--") && argument.includes("=")) {
      const separator = argument.indexOf("=");
      if (options.has(argument.slice(0, separator))) {
        values.push(...argument.slice(separator + 1).split(","));
      }
      continue;
    }
    if (options.has(argument)) {
      if (args[index + 1]) values.push(...args[index + 1]!.split(","));
      index += 1;
      continue;
    }
    const shortOption = argument.slice(0, 2);
    if (argument.length > 2 && options.has(shortOption)) {
      values.push(...argument.slice(2).split(","));
    }
  }
  return values;
}

function optionValues(args: string[], names: ReadonlySet<string>): string[] {
  const values: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index]!;
    const equals = argument.indexOf("=");
    if (equals > 0 && names.has(argument.slice(0, equals))) {
      values.push(argument.slice(equals + 1));
    } else if (names.has(argument) && args[index + 1]) {
      values.push(args[index + 1]!);
      index += 1;
    } else if (argument.length > 2 && names.has(argument.slice(0, 2))) {
      values.push(argument.slice(2));
    }
  }
  return values;
}

function colonFields(value: string): string[] {
  const fields: string[] = [];
  let current = "";
  let bracketed = false;
  for (const char of value) {
    if (char === "[") bracketed = true;
    if (char === "]") bracketed = false;
    if (char === ":" && !bracketed) {
      fields.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  fields.push(current);
  return fields;
}

function curlOverrideHosts(args: string[]): string[] {
  const hosts: string[] = [];
  for (const value of optionValues(args, new Set(["--resolve"]))) {
    const fields = colonFields(value);
    for (const address of fields.slice(2).join(":").split(",")) {
      const host = hostFromToken(address);
      if (host) hosts.push(host);
    }
  }
  for (const value of optionValues(args, new Set(["--connect-to"]))) {
    const fields = colonFields(value);
    const host = hostFromToken(fields[2] ?? "");
    if (host) hosts.push(host);
  }
  return hosts;
}

function sshRoutingHosts(args: string[]): string[] {
  const hosts: string[] = [];
  for (const value of optionValues(args, new Set(["-L", "-R", "-W"]))) {
    const fields = colonFields(value);
    const candidate = fields.length >= 2 ? fields[fields.length - 2]! : fields[0]!;
    const host = hostFromToken(candidate);
    if (host) hosts.push(host);
  }
  for (const value of optionValues(args, new Set(["-o"]))) {
    const separator = value.indexOf("=");
    if (separator < 0) continue;
    const key = value.slice(0, separator).toLowerCase();
    const optionValue = value.slice(separator + 1);
    if (key === "proxyjump") {
      for (const jump of optionValue.split(",")) {
        const host = hostFromToken(jump);
        if (host) hosts.push(host);
      }
    } else if (key === "proxycommand") {
      const proxy = invocationFromSegment(optionValue, true);
      if (proxy && NETWORK_TOOL_NAMES.has(proxy.tool)) {
        hosts.push(...hostsFromNetworkInvocation(proxy.tool, proxy.args));
      }
    }
  }
  for (const argument of args) {
    const match = argument.match(/^-o(?:ProxyJump|ProxyCommand)=(.+)$/i);
    if (!match) continue;
    const synthetic = sshRoutingHosts(["-o", argument.slice(2)]);
    hosts.push(...synthetic);
  }
  return hosts;
}

/**
 * Whether a short-option token consumes the argument that follows it.
 *
 * Short options bundle: in `curl -sX POST`, the value-taking option is the last
 * letter of the bundle, so `POST` is `-X`'s value and not a destination.
 * Checking only two-character tokens made every such bundle leak its value into
 * destination position, where `POST` canonicalises to the host `post`.
 * A value attached inside the bundle (`wget -qO-`) consumes nothing further.
 */

function shortBundleTakesNextArgument(
  argument: string,
  valueOptions: ReadonlySet<string>,
): boolean {
  for (let position = 1; position < argument.length; position += 1) {
    if (!valueOptions.has("-" + argument[position]!)) continue;
    return position === argument.length - 1;
  }
  return false;
}

function positionalArgs(tool: string, args: string[]): string[] {
  const positions: string[] = [];
  const valueOptions = TOOL_VALUE_OPTIONS[tool] ?? new Set<string>();
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index]!;
    if (argument === "--") {
      positions.push(...args.slice(index + 1));
      break;
    }
    if (argument.startsWith("--")) {
      if (!argument.includes("=") && valueOptions.has(argument)) index += 1;
      continue;
    }
    if (argument.startsWith("-")) {
      if (shortBundleTakesNextArgument(argument, valueOptions)) index += 1;
      continue;
    }
    positions.push(argument);
  }
  return positions;
}

export function hostsFromNetworkInvocation(tool: string, args: string[]): string[] {
  if (tool === "scp" || tool === "rsync") {
    const remoteHosts = positionalArgs(tool, args)
      .filter((argument) => argument.includes(":") || argument.includes("@"))
      .map(hostFromToken)
      .filter((host): host is string => host !== null);
    return tool === "scp"
      ? [...remoteHosts, ...hostOptionValues(tool, args), ...sshRoutingHosts(args)]
          .map(hostFromToken)
          .filter((host): host is string => host !== null)
      : remoteHosts;
  }
  if (tool === "openssl") {
    const hosts: string[] = [];
    for (let index = 0; index < args.length - 1; index += 1) {
      if (args[index] === "-connect" || args[index] === "-proxy") {
        const host = hostFromToken(args[index + 1]!);
        if (host) hosts.push(host);
      }
    }
    return hosts;
  }
  if (tool === "socat") return socatHosts(args);
  let positionals = positionalArgs(tool, args);
  if ((tool === "http" || tool === "httpie" || tool === "xh") && /^[A-Z]+$/.test(positionals[0] ?? "")) {
    positionals = positionals.slice(1);
  }
  // Only the first host-shaped positional is the destination. Anything after it
  // is a remote command, which nestedCommands() analyses on its own.
  const destinations = ONE_DESTINATION_TOOLS.has(tool)
    ? positionals.filter((argument) => hostFromToken(argument) !== null).slice(0, 1)
    : positionals;
  const special = [
    ...(tool === "curl" ? curlOverrideHosts(args) : []),
    ...(tool === "ssh" || tool === "sftp" ? sshRoutingHosts(args) : []),
  ];
  return [...destinations, ...hostOptionValues(tool, args), ...special]
    .map(hostFromToken)
    .filter((host): host is string => host !== null);
}

// socat names its address family before the destination, and the connecting
// families are far wider than `TCP:`/`UDP:` — `TCP-CONNECT:`, `OPENSSL:` and
// `SOCKS4:` all reach a host. LISTEN/RECV families are deliberately absent:
// they bind locally and carry a bare port, which must not be read as a host.

const SOCAT_CONNECT_ADDRESS =
  /^(tcp|udp|sctp|dccp|openssl|ssl|socks4a?|socks5|proxy)[46]?(?:-connect|-c)?:(.+)$/i;

function socatHosts(args: string[]): string[] {
  const hosts: string[] = [];
  for (const argument of args) {
    const match = argument.match(SOCAT_CONNECT_ADDRESS);
    if (!match) continue;
    const fields = colonFields(match[2]!);
    // Proxy families name the proxy first and the real target second.
    const isProxy = /socks|proxy/i.test(match[1]!);
    for (const field of fields.slice(0, isProxy ? 2 : 1)) {
      const host = hostFromToken(field.split(",")[0]!);
      if (host) hosts.push(host);
    }
  }
  return hosts;
}