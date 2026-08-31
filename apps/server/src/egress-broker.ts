import { createServer, createConnection, type Server, type Socket } from "node:net";
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

  if (version === 4) return isForbiddenIPv4(address);

  const lower = address.toLowerCase();
  // IPv4-mapped (::ffff:10.0.0.1) carries an IPv4 address inside an IPv6
  // literal; classify it as the IPv4 address it actually is.
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
  if (mapped) return isForbiddenIPv4(mapped[1]!);

  if (lower === "::1" || lower === "::") return true;
  if (lower.startsWith("fe8") || lower.startsWith("fe9")) return true; // fe80::/10
  if (lower.startsWith("fea") || lower.startsWith("feb")) return true;
  if (/^f[cd]/.test(lower)) return true; // fc00::/7 unique local
  if (lower.startsWith("ff")) return true; // multicast
  return false;
}

function isForbiddenIPv4(address: string): boolean {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b] = parts as [number, number, number, number];
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

export interface BrokerOptions {
  allow: EgressEndpoint;
  /** Injectable for tests; defaults to real DNS. */
  resolve?: (hostname: string) => Promise<string[]>;
  /**
   * Injectable for tests; defaults to a real TCP connection. A seam here rather
   * than relaxing isForbiddenAddress, so the tunnel can be exercised against a
   * loopback echo server without ever teaching the broker to permit loopback.
   */
  dial?: (target: { host: string; port: number }, onReady: () => void) => Socket;
  onDenied?: (reason: string, target: string) => void;
}

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

  return createServer((client) => {
    client.once("error", () => client.destroy());
    client.once("data", (chunk) => {
      void (async () => {
        const target = parseConnectTarget(chunk.toString("latin1"));
        if (!target) {
          return deny(client, "400 Bad Request", "not a CONNECT request", "-");
        }
        const label = target.host + ":" + target.port;

        // Allowlist first: an unknown name is never even resolved, so the
        // broker cannot be used as a DNS oracle for arbitrary hostnames.
        if (target.host !== options.allow.host || target.port !== options.allow.port) {
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

        const upstream = dial({ host: addresses[0]!, port: target.port }, () => {
          client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
          client.pipe(upstream);
          upstream.pipe(client);
        });
        upstream.once("error", () => {
          upstream.destroy();
          if (!client.destroyed) deny(client, "502 Bad Gateway", "upstream failed", label);
        });
        client.once("close", () => upstream.destroy());
      })();
    });
  });
}
