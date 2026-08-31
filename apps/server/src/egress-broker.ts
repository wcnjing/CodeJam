import { createServer, createConnection, type Server, type Socket } from "node:net";
import { createSocket, type Socket as DgramSocket } from "node:dgram";
import { getServers } from "node:dns";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

/**
 * A destination-restricted HTTP CONNECT proxy.
 *
 * The command policy is a guard in front of a network the Agent can still
 * reach; anything it fails to recognise — a base64-encoded command, a binary it
 * did not model — reaches the internet anyway. This broker removes the network
 * instead of describing it: the Agent container is attached to a network with
 * no route out, and this process is its only edge. A destination that is not
 * the one configured endpoint has nowhere to go, encoded or not.
 *
 * Fails closed everywhere: an unparseable request, a non-allowlisted target, a
 * DNS failure, or a resolved address in a private range all end the socket
 * without connecting anything.
 *
 * The broker also answers DNS for the Agent network (see createDnsForwarder):
 * an `--internal` network has no outbound DNS, so without this the Agent could
 * not resolve anything, allowlisted hosts included. Resolution through the
 * broker opens no hole — answers alone cannot carry data; every connection is
 * still gated by the CONNECT allowlist or has no route out.
 */

export interface EgressEndpoint {
  host: string;
  port: number;
}

/**
 * Blocks addresses that are reachable from the broker but must never be
 * reachable through it.
 *
 * The important case is DNS rebinding: an allowlisted hostname is not a
 * guarantee about the address it resolves to, and an attacker who controls the
 * DNS record for a name we allow can point it at 127.0.0.1 or at the cloud
 * metadata service on 169.254.169.254 and borrow the broker's own network
 * position. Checking the hostname string alone — the obvious implementation —
 * leaves exactly that hole, so every resolved address is re-checked here
 * immediately before connecting.
 */
export function isForbiddenAddress(address: string): boolean {
  const version = isIP(address);
  if (version === 0) return true; // not an address at all: fail closed

  if (version === 4) {
    const bytes = ipv4Bytes(address);
    return bytes === null ? true : isForbiddenIPv4(bytes);
  }

  // Decided on the address's bytes, never on how it happens to be spelled.
  // getaddrinfo returns the hex form (::ffff:7f00:1), so a textual check for
  // the dotted-quad spelling ("::ffff:127.0.0.1") misses the very case this
  // function exists to stop: a hostile AAAA record for the allowlisted name
  // pointing at loopback or at the metadata service.
  const bytes = ipv6Bytes(address);
  return bytes === null ? true : isForbiddenIPv6(bytes);
}

function ipv4Bytes(address: string): Uint8Array | null {
  const parts = address.split(".");
  if (parts.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let index = 0; index < 4; index += 1) {
    const part = parts[index]!;
    if (!/^\d{1,3}$/.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    bytes[index] = value;
  }
  return bytes;
}

/** Expands an IPv6 literal — `::` compression and a trailing dotted quad included. */
function ipv6Bytes(address: string): Uint8Array | null {
  const text = address.toLowerCase().split("%")[0]!; // drop any zone id
  const halves = text.split("::");
  if (halves.length > 2) return null;

  const expand = (part: string): number[] | null => {
    if (part === "") return [];
    const groups = part.split(":");
    const out: number[] = [];
    for (let index = 0; index < groups.length; index += 1) {
      const group = groups[index]!;
      if (group.includes(".")) {
        // A dotted quad is only legal as the final group.
        if (index !== groups.length - 1) return null;
        const quad = ipv4Bytes(group);
        if (!quad) return null;
        out.push(quad[0]!, quad[1]!, quad[2]!, quad[3]!);
        continue;
      }
      if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
      const value = Number.parseInt(group, 16);
      out.push(value >> 8, value & 0xff);
    }
    return out;
  };

  const head = expand(halves[0]!);
  const tail = halves.length === 2 ? expand(halves[1]!) : [];
  if (!head || !tail) return null;

  const bytes = new Uint8Array(16);
  if (halves.length === 1) {
    if (head.length !== 16) return null;
    bytes.set(head);
    return bytes;
  }
  // `::` has to stand for at least one zero group, or the literal is malformed.
  if (head.length + tail.length > 14) return null;
  bytes.set(head, 0);
  bytes.set(tail, 16 - tail.length);
  return bytes;
}

function isForbiddenIPv4(bytes: Uint8Array): boolean {
  const [a, b] = bytes as unknown as [number, number, number, number];
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // RFC1918
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local, incl. metadata 169.254.169.254
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918
  if (a === 192 && b === 168) return true; // RFC1918
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true; // multicast and reserved, incl. 255.255.255.255
  return false;
}

function isForbiddenIPv6(b: Uint8Array): boolean {
  const zeroesThrough = (count: number) => b.slice(0, count).every((byte) => byte === 0);

  if (zeroesThrough(15) && (b[15] === 0 || b[15] === 1)) return true; // :: and ::1

  // Both IPv4-mapped (::ffff:0:0/96) and IPv4-compatible (::/96) carry an IPv4
  // address in the low four bytes. Classify each as the IPv4 address it is.
  if (zeroesThrough(10) && b[10] === 0xff && b[11] === 0xff) return isForbiddenIPv4(b.slice(12));
  if (zeroesThrough(12)) return isForbiddenIPv4(b.slice(12));

  if (b[0] === 0xff) return true; // ff00::/8 multicast
  if (b[0] === 0xfe && (b[1]! & 0xc0) === 0x80) return true; // fe80::/10 link-local
  if (b[0] === 0xfe && (b[1]! & 0xc0) === 0xc0) return true; // fec0::/10 site-local (deprecated)
  if ((b[0]! & 0xfe) === 0xfc) return true; // fc00::/7 unique local

  // 6to4 and Teredo are both ways of naming an IPv4 destination in an IPv6
  // literal. 6to4 embeds the address in the clear; Teredo obfuscates the client
  // half, so the whole deprecated prefix goes rather than half of it.
  if (b[0] === 0x20 && b[1] === 0x02) return isForbiddenIPv4(b.slice(2, 6));
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && b[3] === 0x00) return true;

  return false;
}

/** Parses `https://host[:port]/path` into the endpoint the Agent may reach. */
export function parseEgressEndpoint(baseUrl: string): EgressEndpoint {
  const url = new URL(baseUrl);
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Egress endpoint must be http or https: " + baseUrl);
  }
  const port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("Egress endpoint has an invalid port: " + baseUrl);
  }
  return { host: url.hostname.toLowerCase(), port };
}

/**
 * Parses a comma-separated EGRESS_ALLOW_URL into the endpoints the Agent may
 * reach. The broker's allowlist used to be a single endpoint (the model API);
 * it is now the model API plus the effective command-policy allowlist, so a
 * host an operator has allowlisted is actually reachable, not just
 * policy-allowed. Duplicates collapse; empty input yields an empty list, which
 * the CLI refuses.
 */
export function parseEgressEndpoints(raw: string): EgressEndpoint[] {
  const seen = new Set<string>();
  const endpoints: EgressEndpoint[] = [];
  for (const part of raw.split(",")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const endpoint = parseEgressEndpoint(trimmed);
    const key = endpoint.host + ":" + endpoint.port;
    if (seen.has(key)) continue;
    seen.add(key);
    endpoints.push(endpoint);
  }
  return endpoints;
}

export interface BrokerOptions {
  /** Every destination the Agent may reach; anything else is refused. */
  allow: EgressEndpoint[];
  /** Injectable for tests; defaults to real DNS. */
  resolve?: (hostname: string) => Promise<string[]>;
  /**
   * Injectable for tests; defaults to a real TCP connection. A seam here rather
   * than relaxing isForbiddenAddress, so the tunnel can be exercised against a
   * loopback echo server without ever teaching the broker to permit loopback.
   */
  dial?: (target: { host: string; port: number }, onReady: () => void) => Socket;
  onDenied?: (reason: string, target: string) => void;
  /**
   * How long a client has to finish its request head. The broker is the Agent's
   * only edge, so a socket that opens and then dribbles must not hold it open
   * indefinitely.
   */
  headTimeoutMs?: number;
}

/** A CONNECT head is one short line; anything larger is not one. */
const MAX_HEAD_BYTES = 8_192;

async function defaultResolve(hostname: string): Promise<string[]> {
  if (isIP(hostname) !== 0) return [hostname];
  const results = await lookup(hostname, { all: true });
  return results.map((r) => r.address);
}

/** `CONNECT host:port HTTP/1.1` — the only verb this proxy implements. */
function parseConnectTarget(head: string): EgressEndpoint | null {
  const line = head.split("\r\n", 1)[0] ?? "";
  const match = /^CONNECT\s+(\S+)\s+HTTP\/1\.[01]$/i.exec(line.trim());
  if (!match) return null;
  const authority = match[1]!;
  const separator = authority.lastIndexOf(":");
  if (separator < 1) return null;
  const host = authority.slice(0, separator).toLowerCase();
  const port = Number(authority.slice(separator + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host, port };
}

export function createEgressBroker(options: BrokerOptions): Server {
  const resolve = options.resolve ?? defaultResolve;
  const dial = options.dial ?? ((target, onReady) => createConnection(target, onReady));
  const deny = (socket: Socket, code: string, reason: string, target: string) => {
    options.onDenied?.(reason, target);
    socket.end("HTTP/1.1 " + code + "\r\nConnection: close\r\n\r\n");
  };

  /**
   * Connects to the first address that answers.
   *
   * Every address has already been through isForbiddenAddress, so trying more
   * than one widens nothing. It fixes an availability hole instead: a dual
   * stack name whose AAAA sorts first is unreachable from a container with no
   * IPv6 route, even though the A record would have worked.
   */
  const connectToAny = async (addresses: string[], port: number): Promise<Socket | null> => {
    for (const address of addresses) {
      const socket = await new Promise<Socket | null>((resolve_) => {
        let settled = false;
        const attempt = dial({ host: address, port }, () => {
          if (settled) return;
          settled = true;
          attempt.off("error", onError);
          resolve_(attempt);
        });
        function onError() {
          if (settled) return;
          settled = true;
          attempt.destroy();
          resolve_(null);
        }
        attempt.once("error", onError);
      });
      if (socket) return socket;
    }
    return null;
  };

  return createServer((client) => {
    let head = "";
    let settled = false;

    // A client that never finishes its request head is dropped rather than
    // left holding the Agent's only edge open.
    const headTimer = setTimeout(() => {
      if (settled) return;
      settled = true;
      client.destroy();
    }, options.headTimeoutMs ?? 10_000);
    headTimer.unref();

    client.once("error", () => {
      clearTimeout(headTimer);
      client.destroy();
    });
    client.once("close", () => clearTimeout(headTimer));

    client.on("data", (chunk: Buffer) => {
      if (settled) return;
      head += chunk.toString("latin1");
      // A head can arrive split across segments; reading only the first chunk
      // turns ordinary segmentation into a 400, which presents as an
      // intermittent model outage rather than as anything to do with the proxy.
      const end = head.indexOf("\r\n\r\n");
      if (end === -1) {
        if (head.length > MAX_HEAD_BYTES) {
          settled = true;
          clearTimeout(headTimer);
          deny(client, "400 Bad Request", "request head too large", "-");
        }
        return;
      }

      settled = true;
      clearTimeout(headTimer);
      // Anything the client pipelined behind the head has already been handed
      // to us, so it is not in the socket's buffer and pipe() will not see it.
      const pipelined = Buffer.from(head.slice(end + 4), "latin1");
      // Pause before detaching, so bytes that arrive while DNS is in flight
      // stay buffered for pipe() instead of being dropped on the floor.
      client.pause();
      client.removeAllListeners("data");
      void handle(head.slice(0, end), pipelined);
    });

    const handle = async (requestHead: string, pipelined: Buffer): Promise<void> => {
      const target = parseConnectTarget(requestHead);
      if (!target) {
        return deny(client, "400 Bad Request", "not a CONNECT request", "-");
      }
      const label = target.host + ":" + target.port;

      // Allowlist first: an unknown name is never even resolved, so the
      // broker cannot be used as a DNS oracle for arbitrary hostnames.
      const allowed = options.allow.some(
        (endpoint) => endpoint.host === target.host && endpoint.port === target.port,
      );
      if (!allowed) {
        return deny(client, "403 Forbidden", "destination not allowlisted", label);
      }

      let addresses: string[];
      try {
        addresses = await resolve(target.host);
      } catch {
        return deny(client, "502 Bad Gateway", "DNS resolution failed", label);
      }
      if (addresses.length === 0) {
        return deny(client, "502 Bad Gateway", "DNS returned no addresses", label);
      }
      // EVERY address, not just the one we connect to: a name that resolves to
      // both a public and a private address is a rebinding attempt.
      const forbidden = addresses.find((address) => isForbiddenAddress(address));
      if (forbidden) {
        return deny(client, "403 Forbidden", "resolves to a private address", label);
      }

      const upstream = await connectToAny(addresses, target.port);
      if (!upstream) {
        return deny(client, "502 Bad Gateway", "upstream failed", label);
      }
      if (client.destroyed) {
        upstream.destroy();
        return;
      }

      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (pipelined.length > 0) upstream.write(pipelined);
      client.pipe(upstream);
      upstream.pipe(client);

      // Past this point the socket carries opaque TLS bytes. Writing a status
      // line into it injects garbage into the record the client is parsing, so
      // a failure now is a teardown and nothing else.
      const tearDown = () => {
        upstream.destroy();
        client.destroy();
      };
      upstream.once("error", tearDown);
      upstream.once("close", tearDown);
      client.once("close", tearDown);
    };
  });
}

// ---------------------------------------------------------------------------
// DNS forwarding
// ---------------------------------------------------------------------------

export interface DnsForwarderOptions {
  /** Port to listen on. 53 in production; injectable for tests. */
  port?: number;
  /**
   * Upstream nameservers to relay queries to, as `host` or `host:port`.
   * Defaults to the process's configured resolvers (the broker container's
   * /etc/resolv.conf, which under the engine points at its embedded DNS and
   * therefore resolves external names).
   */
  upstreams?: readonly string[];
  /**
   * How long to wait for an upstream answer before trying the next resolver.
   * Injectable so tests run fast.
   */
  upstreamTimeoutMs?: number;
}

/**
 * A tiny DNS forwarder, UDP and TCP, dependency-free.
 *
 * The Agent's `--internal` network has no outbound DNS at all (the engine's
 * embedded resolver refuses to forward external queries there), so an
 * allowlisted host could not even be resolved from the Agent container. This
 * gives the broker — already the Agent's only edge — the second half of the
 * job: it answers the Agent's queries by relaying them verbatim to the
 * broker's own resolvers. Resolution is not a data channel: answers alone
 * carry nothing out, and every connection is still gated by the CONNECT
 * allowlist or has no route.
 *
 * Only node builtins, so the sidecar image keeps its no-dependency property.
 */
export function createDnsForwarder(options: DnsForwarderOptions = {}) {
  const port = options.port ?? 53;
  const upstreams =
    options.upstreams && options.upstreams.length > 0
      ? options.upstreams.map(normalizeUpstream)
      : getServers().map((server) => ({ host: server, port: 53 }));
  if (upstreams.length === 0) {
    throw new Error("DNS forwarder has no upstream resolvers to relay to");
  }
  const timeoutMs = options.upstreamTimeoutMs ?? 2_000;

  const udp = createSocket("udp4");

  udp.on("message", (query, rinfo) => {
    // Remember the client's transaction id: an upstream resolver may rewrite
    // it, and the client will drop a response whose id does not match its
    // query.
    const originalId = query.readUInt16BE(0);
    relayUdp(query, (answer) => {
      const restored = Buffer.from(answer);
      restored.writeUInt16BE(originalId, 0);
      udp.send(restored, rinfo.port, rinfo.address);
    });
  });

  function relayUdp(query: Buffer, onAnswer: (answer: Buffer) => void): void {
    let attempt = 0;
    let done = false;
    let timer: NodeJS.Timeout | null = null;
    let socket: DgramSocket | null = null;

    const cleanup = () => {
      if (timer) clearTimeout(timer);
      if (socket) {
        const closing = socket;
        socket = null;
        closing.close();
      }
    };

    const next = () => {
      if (done) return;
      cleanup();
      const upstream = upstreams[attempt];
      if (!upstream) {
        // Every resolver failed; drop the query (the client retries).
        done = true;
        return;
      }
      attempt += 1;
      socket = createSocket("udp4");
      socket.once("message", (answer) => {
        done = true;
        cleanup();
        onAnswer(answer);
      });
      // Error or timeout: move to the next resolver with a fresh socket.
      socket.once("error", () => next());
      timer = setTimeout(() => next(), timeoutMs);
      socket.send(query, upstream.port, upstream.host);
    };

    next();
  }

  // TCP is the retry path for large answers (the client sets TC and retries
  // over TCP). Relay the length-prefixed stream verbatim.
  const tcp = createServer((client) => {
    const upstream = netUpstream(upstreams);
    if (!upstream) {
      client.destroy();
      return;
    }
    const up = createConnection({ host: upstream.host, port: upstream.port });
    client.pipe(up).pipe(client);
    client.on("error", () => up.destroy());
    up.on("error", () => client.destroy());
  });

  udp.bind(port);
  tcp.listen(port);

  return { udp, tcp };
}

interface UpstreamAddress {
  host: string;
  port: number;
}

function normalizeUpstream(raw: string): UpstreamAddress {
  const trimmed = raw.trim();
  const separator = trimmed.lastIndexOf(":");
  if (separator > 0) {
    const port = Number(trimmed.slice(separator + 1));
    if (Number.isInteger(port) && port >= 1 && port <= 65535) {
      return { host: trimmed.slice(0, separator), port };
    }
  }
  return { host: trimmed, port: 53 };
}

function netUpstream(upstreams: UpstreamAddress[]): UpstreamAddress | null {
  return upstreams[0] ?? null;
}
