import { createConnection, createServer, type Server } from "node:net";
import { createSocket, type Socket as DgramSocket } from "node:dgram";
import { afterEach, describe, expect, it } from "vitest";
import {
  createDnsForwarder,
  createEgressBroker,
  isForbiddenAddress,
  parseEgressEndpoint,
  parseEgressEndpoints,
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

  it("blocks IPv4-mapped addresses however they are spelled", () => {
    // The textual check only recognised the dotted-quad spelling. getaddrinfo
    // hands back the hex form, so a hostile AAAA record for the allowlisted
    // name — the exact rebinding case this function exists to stop — resolved
    // to ::ffff:7f00:1 and connected straight to 127.0.0.1.
    for (const address of [
      "::ffff:7f00:1", // 127.0.0.1
      "::ffff:a9fe:a9fe", // 169.254.169.254, the metadata service
      "::ffff:a00:1", // 10.0.0.1
      "::ffff:c0a8:1", // 192.168.0.1
    ]) {
      expect(isForbiddenAddress(address), address).toBe(true);
    }
  });

  it("blocks IPv6 forms that embed or reach a private IPv4 address", () => {
    for (const address of [
      "fec0::1", // deprecated site-local
      "::127.0.0.1", // IPv4-compatible
      "2002:7f00:1::1", // 6to4 wrapping 127.0.0.1
      "2001:0:7f00:1::1", // Teredo
    ]) {
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

  it("parses a comma-separated allowlist, lowercasing and deduping", () => {
    expect(
      parseEgressEndpoints(
        "https://Ark.Example.invalid, https://google.com:8443,https://ark.example.invalid",
      ),
    ).toEqual([
      { host: "ark.example.invalid", port: 443 },
      { host: "google.com", port: 8443 },
    ]);
    // Empty input is an empty allowlist; the CLI refuses to run with it.
    expect(parseEgressEndpoints("  ,  ")).toEqual([]);
    expect(() => parseEgressEndpoints("not-a-url")).toThrow();
  });
});

describe("egress broker", () => {
  it("refuses everything when the allowlist is empty", async () => {
    // The CLI refuses to start on an empty EGRESS_ALLOW_URL, so this is the
    // belt to that braces: if an empty list ever reaches the server anyway, it
    // must mean "nothing" and never "anything". Fail-closed is a property of
    // the matcher, not only of the argument check in front of it.
    const port = await listen(createEgressBroker({ allow: [], resolve: async () => ["8.8.8.8"] }));
    expect(await connect(port, "CONNECT ark.example.invalid:443 HTTP/1.1\r\n\r\n")).toContain(
      "403",
    );
  });

  it("refuses a destination that is not the allowlisted one", async () => {
    const port = await listen(createEgressBroker({ allow: [ALLOW], resolve: async () => ["8.8.8.8"] }));
    const response = await connect(port, "CONNECT evil.example.invalid:443 HTTP/1.1\r\n\r\n");
    expect(response).toContain("403");
  });

  it("tunnels to any allowlisted endpoint, not just the first", async () => {
    // The whole point of a widened broker allowlist: a host the operator
    // allowlisted (or approved) is actually reachable, while everything that is
    // still not on the list is refused exactly as before.
    const upstream = createServer((socket) => {
      socket.on("data", (chunk) => socket.end("echo:" + chunk.toString("utf8")));
    });
    const upstreamPort = await listen(upstream);

    const brokerPort = await listen(
      createEgressBroker({
        allow: [
          { host: "ark.example.invalid", port: 443 },
          { host: "google.com", port: 443 },
        ],
        resolve: async () => ["93.184.216.34"],
        dial: (_target, onReady) =>
          createConnection({ host: "127.0.0.1", port: upstreamPort }, onReady),
      }),
    );

    const response = await connect(
      brokerPort,
      "CONNECT google.com:443 HTTP/1.1\r\n\r\n",
      "ping",
    );
    expect(response).toContain("200 Connection Established");
    expect(response).toContain("echo:ping");

    // A destination on neither endpoint is still refused before any DNS.
    const refused = await connect(
      brokerPort,
      "CONNECT evil.example.invalid:443 HTTP/1.1\r\n\r\n",
    );
    expect(refused).toContain("403");
  });

  it("refuses the right host on the wrong port", async () => {
    const port = await listen(createEgressBroker({ allow: [ALLOW], resolve: async () => ["8.8.8.8"] }));
    const response = await connect(port, "CONNECT ark.example.invalid:22 HTTP/1.1\r\n\r\n");
    expect(response).toContain("403");
  });

  it("never resolves a non-allowlisted name, so it cannot be a DNS oracle", async () => {
    const asked: string[] = [];
    const port = await listen(
      createEgressBroker({ allow: [ALLOW], resolve: async (h) => { asked.push(h); return ["8.8.8.8"]; } }),
    );
    await connect(port, "CONNECT internal.corp.invalid:443 HTTP/1.1\r\n\r\n");
    expect(asked).toEqual([]);
  });

  it("refuses an allowlisted name that resolves to a private address", async () => {
    // The rebinding case: the name is allowed, the address is not.
    const port = await listen(
      createEgressBroker({ allow: [ALLOW], resolve: async () => ["127.0.0.1"] }),
    );
    const response = await connect(port, "CONNECT ark.example.invalid:443 HTTP/1.1\r\n\r\n");
    expect(response).toContain("403");
  });

  it("refuses when any one of several answers is private", async () => {
    const port = await listen(
      createEgressBroker({ allow: [ALLOW], resolve: async () => ["93.184.216.34", "169.254.169.254"] }),
    );
    const response = await connect(port, "CONNECT ark.example.invalid:443 HTTP/1.1\r\n\r\n");
    expect(response).toContain("403");
  });

  it("fails closed when DNS fails or returns nothing", async () => {
    const failing = await listen(
      createEgressBroker({ allow: [ALLOW], resolve: async () => { throw new Error("SERVFAIL"); } }),
    );
    expect(await connect(failing, "CONNECT ark.example.invalid:443 HTTP/1.1\r\n\r\n")).toContain("502");

    const empty = await listen(createEgressBroker({ allow: [ALLOW], resolve: async () => [] }));
    expect(await connect(empty, "CONNECT ark.example.invalid:443 HTTP/1.1\r\n\r\n")).toContain("502");
  });

  it("refuses anything that is not a CONNECT request", async () => {
    const port = await listen(createEgressBroker({ allow: [ALLOW], resolve: async () => ["8.8.8.8"] }));
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
        allow: [ALLOW],
        resolve: async () => ["93.184.216.34"],
        dial: (_target, onReady) =>
          createConnection({ host: "127.0.0.1", port: upstreamPort }, onReady),
      }),
    );

    const response = await connect(brokerPort, "CONNECT ark.example.invalid:443 HTTP/1.1\r\n\r\n", "ping");
    expect(response).toContain("200 Connection Established");
    expect(response).toContain("echo:ping");
  });

  it("does not write an HTTP error into an established tunnel", async () => {
    // Once the 200 is sent the socket carries opaque TLS bytes. Writing a
    // status line into it injects garbage into the stream the client is parsing
    // as a TLS record; the tunnel is over, so it should simply be torn down.
    const upstream = createServer(() => {
      /* accepts and holds; the failure is injected below */
    });
    const upstreamPort = await listen(upstream);

    const brokerPort = await listen(
      createEgressBroker({
        allow: [ALLOW],
        resolve: async () => ["93.184.216.34"],
        dial: (_target, onReady) => {
          const socket = createConnection({ host: "127.0.0.1", port: upstreamPort }, () => {
            onReady();
            // The upstream fails after the tunnel is up — a reset mid-session.
            // This is the real "upstream failed" handler, not a stand-in.
            setTimeout(() => socket.emit("error", new Error("upstream reset")), 20);
          });
          return socket;
        },
      }),
    );

    const response = await connect(
      brokerPort,
      "CONNECT ark.example.invalid:443 HTTP/1.1\r\n\r\n",
    );
    expect(response).toContain("200 Connection Established");
    expect(response).not.toContain("502");
    expect(response).not.toContain("Bad Gateway");
  });

  it("accepts a CONNECT line split across TCP segments", async () => {
    // A client is free to flush the request in pieces. Reading only the first
    // chunk turns an ordinary segmentation into a 400, which presents as an
    // intermittent model outage rather than as anything to do with the proxy.
    const upstream = createServer((socket) => {
      socket.on("data", (chunk) => socket.end("echo:" + chunk.toString("utf8")));
    });
    const upstreamPort = await listen(upstream);

    const brokerPort = await listen(
      createEgressBroker({
        allow: [ALLOW],
        resolve: async () => ["93.184.216.34"],
        dial: (_target, onReady) =>
          createConnection({ host: "127.0.0.1", port: upstreamPort }, onReady),
      }),
    );

    const response = await new Promise<string>((resolve, reject) => {
      const socket = createConnection({ host: "127.0.0.1", port: brokerPort }, () => {
        socket.write("CONNECT ark.example.inv");
        setTimeout(() => socket.write("alid:443 HTTP/1.1\r\n\r\n"), 30);
      });
      let buffer = "";
      let sent = false;
      socket.setTimeout(4000, () => {
        socket.destroy();
        reject(new Error("timeout"));
      });
      socket.on("data", (chunk: Buffer) => {
        buffer += chunk.toString("latin1");
        if (!sent && buffer.includes("200 Connection Established")) {
          sent = true;
          socket.write("ping");
        }
      });
      socket.on("close", () => resolve(buffer));
      socket.on("error", reject);
    });
    expect(response).toContain("200 Connection Established");
    expect(response).toContain("echo:ping");
  });

  it("gives up on a request head that never completes", async () => {
    // Fail closed on a client that opens a socket and dribbles: the broker is
    // the Agent's only edge, so a stuck request must not hold it open forever.
    const brokerPort = await listen(
      createEgressBroker({ allow: [ALLOW], resolve: async () => ["93.184.216.34"], headTimeoutMs: 200 }),
    );

    const closed = await new Promise<boolean>((resolve, reject) => {
      const socket = createConnection({ host: "127.0.0.1", port: brokerPort }, () => {
        socket.write("CONNECT ark.exa");
      });
      socket.setTimeout(4000, () => {
        socket.destroy();
        reject(new Error("broker never gave up on the partial request"));
      });
      socket.on("close", () => resolve(true));
      socket.on("error", () => resolve(true));
    });
    expect(closed).toBe(true);
  });

  it("falls back to the next address when the first will not connect", async () => {
    // An AAAA-first answer in a container with no IPv6 route made the whole
    // endpoint unreachable even though the A record was fine.
    const upstream = createServer((socket) => {
      socket.on("data", (chunk) => socket.end("echo:" + chunk.toString("utf8")));
    });
    const upstreamPort = await listen(upstream);
    const dialled: string[] = [];

    const brokerPort = await listen(
      createEgressBroker({
        allow: [ALLOW],
        resolve: async () => ["2606:4700::1111", "93.184.216.34"],
        dial: (target, onReady) => {
          dialled.push(target.host);
          // The v6 address is routable nowhere here, exactly as in a container
          // with no IPv6: connecting to it fails rather than hanging.
          const port = target.host.includes(":") ? 1 : upstreamPort;
          return createConnection({ host: "127.0.0.1", port }, onReady);
        },
      }),
    );

    const response = await connect(
      brokerPort,
      "CONNECT ark.example.invalid:443 HTTP/1.1\r\n\r\n",
      "ping",
    );
    expect(dialled).toEqual(["2606:4700::1111", "93.184.216.34"]);
    expect(response).toContain("200 Connection Established");
    expect(response).toContain("echo:ping");
  });

  it("reports why a request was denied", async () => {
    const denials: string[] = [];
    const port = await listen(
      createEgressBroker({
        allow: [ALLOW],
        resolve: async () => ["10.0.0.1"],
        onDenied: (reason) => denials.push(reason),
      }),
    );
    await connect(port, "CONNECT ark.example.invalid:443 HTTP/1.1\r\n\r\n");
    expect(denials).toContain("resolves to a private address");
  });
});

describe("DNS forwarder", () => {
  // A fake upstream resolver: echoes the query back with the QR bit set, so the
  // tests can verify the answer was relayed AND that the client's original
  // transaction id survives the round trip (an upstream may rewrite it).
  async function fakeUpstream(): Promise<{
    udp: DgramSocket;
    tcp: Server;
    udpPort: number;
    tcpPort: number;
  }> {
    const udp = createSocket("udp4");
    udp.on("message", (msg, rinfo) => {
      const answer = Buffer.from(msg);
      answer.writeUInt16BE(0x8180, 2); // QR+RD+RA
      udp.send(answer, rinfo.port, rinfo.address);
    });
    const tcp = createServer((socket) => {
      socket.on("data", (chunk) => socket.write(chunk));
    });
    const udpPort = await new Promise<number>((resolve) =>
      udp.bind(0, "127.0.0.1", () => resolve(udp.address().port)),
    );
    const tcpPort = await new Promise<number>((resolve) =>
      tcp.listen(0, "127.0.0.1", () => resolve((tcp.address() as { port: number }).port)),
    );
    return { udp, tcp, udpPort, tcpPort };
  }

  // Starts the forwarder (it binds on creation) and reports the bound ports.
  async function startForwarder(opts: Parameters<typeof createDnsForwarder>[0]): Promise<{
    udp: DgramSocket;
    tcp: Server;
    udpPort: number;
    tcpPort: number;
  }> {
    // Port 53 is privileged; tests bind 0 and read the assigned ports.
    const { udp, tcp } = createDnsForwarder({ ...opts, port: opts.port ?? 0 });
    await Promise.all([
      new Promise<void>((resolve) => udp.once("listening", () => resolve())),
      new Promise<void>((resolve) => tcp.once("listening", () => resolve())),
    ]);
    return {
      udp,
      tcp,
      udpPort: udp.address().port,
      tcpPort: (tcp.address() as { port: number }).port,
    };
  }

  function udpQuery(port: number, query: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const client = createSocket("udp4");
      const timer = setTimeout(() => {
        client.close();
        reject(new Error("dns query timed out"));
      }, 2000);
      client.on("message", (answer) => {
        clearTimeout(timer);
        client.close();
        resolve(answer);
      });
      client.on("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
      client.send(query, port, "127.0.0.1");
    });
  }

  function tcpQuery(port: number, query: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const socket = createConnection({ host: "127.0.0.1", port }, () => {
        const framed = Buffer.alloc(2 + query.length);
        framed.writeUInt16BE(query.length, 0);
        query.copy(framed, 2);
        socket.write(framed);
      });
      let buffer = Buffer.alloc(0);
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error("tcp dns query timed out"));
      }, 2000);
      socket.on("data", (chunk: Buffer) => {
        buffer = Buffer.concat([buffer, chunk]);
        if (buffer.length >= 2 && buffer.length >= 2 + buffer.readUInt16BE(0)) {
          clearTimeout(timer);
          const length = buffer.readUInt16BE(0);
          socket.destroy();
          resolve(buffer.subarray(2, 2 + length));
        }
      });
      socket.on("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
    });
  }

  // One query, hex: id 0x1234, RD, one question for example.com A.
  const QUERY = Buffer.from(
    "123401000001000000000000" + "076578616d706c6503636f6d0000010001",
    "hex",
  );

  it("relays a UDP query to the upstream and keeps the client's transaction id", async () => {
    const upstream = await fakeUpstream();
    const forwarder = await startForwarder({
      upstreams: ["127.0.0.1:" + upstream.udpPort],
      upstreamTimeoutMs: 500,
    });
    try {
      const answer = await udpQuery(forwarder.udpPort, QUERY);
      expect(answer.readUInt16BE(0)).toBe(0x1234);
      expect(answer.readUInt16BE(2) & 0x8000).toBe(0x8000); // QR set: an answer
    } finally {
      forwarder.udp.close();
      forwarder.tcp.close();
      upstream.udp.close();
      upstream.tcp.close();
    }
  });

  it("answers over TCP, the retry path for large responses", async () => {
    const upstream = await fakeUpstream();
    const forwarder = await startForwarder({
      upstreams: ["127.0.0.1:" + upstream.tcpPort],
      upstreamTimeoutMs: 500,
    });
    try {
      const answer = await tcpQuery(forwarder.tcpPort, QUERY);
      expect(answer.readUInt16BE(0)).toBe(0x1234);
    } finally {
      forwarder.udp.close();
      forwarder.tcp.close();
      upstream.udp.close();
      upstream.tcp.close();
    }
  });

  it("tries the next upstream when the first one never answers", async () => {
    // A dead first resolver must not hang the Agent's DNS; the next one serves.
    const upstream = await fakeUpstream();
    const forwarder = await startForwarder({
      upstreams: ["127.0.0.1:1", "127.0.0.1:" + upstream.udpPort],
      upstreamTimeoutMs: 200,
    });
    try {
      const answer = await udpQuery(forwarder.udpPort, QUERY);
      expect(answer.readUInt16BE(0)).toBe(0x1234);
    } finally {
      forwarder.udp.close();
      forwarder.tcp.close();
      upstream.udp.close();
      upstream.tcp.close();
    }
  });
});
