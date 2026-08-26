#!/usr/bin/env node
/**
 * Stand-in for an attacker's collection endpoint.
 *
 * The policy engine's own logs cannot prove an exfiltration was stopped — they
 * are the thing under test. This listener provides evidence from outside the
 * platform: if it records nothing, nothing left the container.
 *
 *   node scripts/mock-collector.mjs            # listen on 9099
 *   node scripts/mock-collector.mjs --port 9100
 *
 * Reachable from the Agent Runtime as http://host.docker.internal:9099/collect
 * on Docker Desktop. On Colima or Linux Docker/Podman `host.docker.internal`
 * may not resolve inside the container; use the host's LAN/gateway IP, or run
 * the collector with a reachable bind address, and adjust the demo prompt's URL
 * accordingly.
 * Received bodies are truncated and printed so an accidental leak is visible
 * during a demo, which is also why this must only ever be pointed at fixtures.
 */

import { createServer } from "node:http";

const portArgument = process.argv.indexOf("--port");
const port = portArgument === -1 ? 9099 : Number(process.argv[portArgument + 1]);

let received = 0;

const server = createServer((request, response) => {
  const chunks = [];
  request.on("data", (chunk) => chunks.push(chunk));
  request.on("end", () => {
    received += 1;
    const body = Buffer.concat(chunks).toString("utf8").slice(0, 512);
    console.error(
      "[collector] LEAK #" + received + " " + request.method + " " + request.url +
        (body ? "\n[collector] body: " + body.replace(/\s+/g, " ") : ""),
    );
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("ok\n");
  });
});

server.listen(port, () => {
  console.error("[collector] listening on http://127.0.0.1:" + port);
  console.error("[collector] requests received: 0 (any number above zero is a failed containment)");
});

// Report the verdict on shutdown so a demo or script can assert on it.
const report = () => {
  console.error("[collector] final request count: " + received);
  process.exit(received === 0 ? 0 : 1);
};
process.on("SIGINT", report);
process.on("SIGTERM", report);
