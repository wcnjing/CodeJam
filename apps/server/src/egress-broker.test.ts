import { createConnection, createServer, type Server } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import {
  createEgressBroker,
  isForbiddenAddress,
  parseEgressEndpoint,
} from "./egress-broker.js";

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(
    servers.splice(0).map((s) => new Promise<void>((done) => s.close(() => done()))),
  );
});

function listen(server: Server): Promise<number> {
  servers.push(server);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve((server.address() as { port: number }).port);
    });
  });
}

/** Sends a raw CONNECT and returns the status line plus any tunnelled bytes. */
function connect(port: number, request: string, thenSend?: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: "127.0.0.1", port }, () => socket.write(request));
    let buffer = "";
    let sent = false;
    socket.setTimeout(4000, () => { socket.destroy(); reject(new Error("timeout")); });
    socket.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("latin1");
      if (thenSend && !sent && buffer.includes("200 Connection Established")) {
        sent = true;
        socket.write(thenSend);
      }
    });
    socket.on("close", () => resolve(buffer));
    socket.on("error", reject);
  });
}

const ALLOW = { host: "ark.example.invalid", port: 443 };

describe("isForbiddenAddress", () => {
  it("blocks loopback, RFC1918, link-local and CGNAT", () => {
    for (const address of [
      "127.0.0.1", "127.9.9.9", "10.0.0.5", "172.16.0.1", "172.31.255.255",
      "192.168.1.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "255.255.255.255",
    ]) {
      expect(isForbiddenAddress(address), address).toBe(true);
    }
  });

  it("blocks the cloud metadata address specifically", () => {
    // The one an escaped Agent actually wants: instance credentials.
    expect(isForbiddenAddress("169.254.169.254")).toBe(true);
  });

  it("blocks IPv6 loopback, link-local, unique-local and IPv4-mapped privates", () => {
    for (const address of ["::1", "::", "fe80::1", "fc00::1", "fd12::3", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.1.2.3"]) {
      expect(isForbiddenAddress(address), address).toBe(true);
    }
  });

  it("allows ordinary public addresses", () => {
    for (const address of ["8.8.8.8", "1.1.1.1", "172.15.0.1", "172.32.0.1", "192.169.0.1", "2606:4700::1111"]) {
      expect(isForbiddenAddress(address), address).toBe(false);
    }
  });

  it("fails closed on anything that is not an address", () => {
    for (const value of ["", "not-an-ip", "999.1.1.1", "10.0.0"]) {
      expect(isForbiddenAddress(value), value).toBe(true);
    }
  });
});

describe("parseEgressEndpoint", () => {
  it("defaults the port by scheme and lowercases the host", () => {
    expect(parseEgressEndpoint("https://Ark.Example.Invalid/api/v3")).toEqual({
      host: "ark.example.invalid", port: 443,
    });
    expect(parseEgressEndpoint("http://ark.example.invalid/api")).toEqual({
      host: "ark.example.invalid", port: 80,
    });
    expect(parseEgressEndpoint("https://ark.example.invalid:8443/api")).toEqual({
      host: "ark.example.invalid", port: 8443,
    });
  });

  it("refuses a non-http scheme", () => {
    expect(() => parseEgressEndpoint("ftp://ark.example.invalid")).toThrow(/http/i);
  });
});

describe("egress broker", () => {
  it("refuses a destination that is not the allowlisted one", async () => {
    const port = await listen(createEgressBroker({ allow: ALLOW, resolve: async () => ["8.8.8.8"] }));
    const response = await connect(port, "CONNECT evil.example.invalid:443 HTTP/1.1\r\n\r\n");
    expect(response).toContain("403");
  });

  it("refuses the right host on the wrong port", async () => {
    const port = await listen(createEgressBroker({ allow: ALLOW, resolve: async () => ["8.8.8.8"] }));
    const response = await connect(port, "CONNECT ark.example.invalid:22 HTTP/1.1\r\n\r\n");
    expect(response).toContain("403");
  });

  it("never resolves a non-allowlisted name, so it cannot be a DNS oracle", async () => {
    const asked: string[] = [];
    const port = await listen(
      createEgressBroker({ allow: ALLOW, resolve: async (h) => { asked.push(h); return ["8.8.8.8"]; } }),
    );
    await connect(port, "CONNECT internal.corp.invalid:443 HTTP/1.1\r\n\r\n");
    expect(asked).toEqual([]);
  });

  it("refuses an allowlisted name that resolves to a private address", async () => {
    // The rebinding case: the name is allowed, the address is not.
    const port = await listen(
      createEgressBroker({ allow: ALLOW, resolve: async () => ["127.0.0.1"] }),
    );
    const response = await connect(port, "CONNECT ark.example.invalid:443 HTTP/1.1\r\n\r\n");
    expect(response).toContain("403");
  });

  it("refuses when any one of several answers is private", async () => {
    const port = await listen(
      createEgressBroker({ allow: ALLOW, resolve: async () => ["93.184.216.34", "169.254.169.254"] }),
    );
    const response = await connect(port, "CONNECT ark.example.invalid:443 HTTP/1.1\r\n\r\n");
    expect(response).toContain("403");
  });

  it("fails closed when DNS fails or returns nothing", async () => {
    const failing = await listen(
      createEgressBroker({ allow: ALLOW, resolve: async () => { throw new Error("SERVFAIL"); } }),
    );
    expect(await connect(failing, "CONNECT ark.example.invalid:443 HTTP/1.1\r\n\r\n")).toContain("502");

    const empty = await listen(createEgressBroker({ allow: ALLOW, resolve: async () => [] }));
    expect(await connect(empty, "CONNECT ark.example.invalid:443 HTTP/1.1\r\n\r\n")).toContain("502");
  });

  it("refuses anything that is not a CONNECT request", async () => {
    const port = await listen(createEgressBroker({ allow: ALLOW, resolve: async () => ["8.8.8.8"] }));
    expect(await connect(port, "GET http://ark.example.invalid/ HTTP/1.1\r\n\r\n")).toContain("400");
  });

  it("tunnels real bytes to the allowlisted destination", async () => {
    // Not just a status code: prove the proxy actually moves data end to end.
    // The upstream is on loopback, which the address check rightly forbids, so
    // DNS answers a public address and the injected dial redirects the actual
    // socket — the guard stays fully armed and the tunnel is still exercised.
    const upstream = createServer((socket) => {
      socket.on("data", (chunk) => socket.end("echo:" + chunk.toString("utf8")));
    });
    const upstreamPort = await listen(upstream);

    const brokerPort = await listen(
      createEgressBroker({
        allow: ALLOW,
        resolve: async () => ["93.184.216.34"],
        dial: (_target, onReady) =>
          createConnection({ host: "127.0.0.1", port: upstreamPort }, onReady),
      }),
    );

    const response = await connect(brokerPort, "CONNECT ark.example.invalid:443 HTTP/1.1\r\n\r\n", "ping");
    expect(response).toContain("200 Connection Established");
    expect(response).toContain("echo:ping");
  });

  it("reports why a request was denied", async () => {
    const denials: string[] = [];
    const port = await listen(
      createEgressBroker({
        allow: ALLOW,
        resolve: async () => ["10.0.0.1"],
        onDenied: (reason) => denials.push(reason),
      }),
    );
    await connect(port, "CONNECT ark.example.invalid:443 HTTP/1.1\r\n\r\n");
    expect(denials).toContain("resolves to a private address");
  });
});
