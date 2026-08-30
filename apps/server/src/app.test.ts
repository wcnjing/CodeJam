import { describe, expect, it } from "vitest";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import type { AgentService } from "./agent-service.js";

const service = {
  listAgents: () => [],
  systemInfo: async () => ({}),
} as unknown as AgentService;

describe("HTTP boundary", () => {
  const ALICE = "tok_alice_0123456789abcdef";

  it("protects API routes with a configured principal token", async () => {
    const app = await createApp(
      loadConfig({ NODE_ENV: "test", APP_PRINCIPALS: "alice:" + ALICE }),
      service,
    );
    const denied = await app.inject({ method: "GET", url: "/api/agents" });
    expect(denied.statusCode).toBe(401);

    const unknown = await app.inject({
      method: "GET",
      url: "/api/agents",
      headers: { authorization: "Bearer tok_wrong_0123456789abcdef" },
    });
    expect(unknown.statusCode).toBe(401);

    const allowed = await app.inject({
      method: "GET",
      url: "/api/agents",
      headers: { authorization: "Bearer " + ALICE },
    });
    expect(allowed.statusCode).toBe(200);
    await app.close();
  });

  it("reports the authenticated principal on /api/me", async () => {
    const app = await createApp(
      loadConfig({ NODE_ENV: "test", APP_PRINCIPALS: "alice:" + ALICE }),
      service,
    );
    const me = await app.inject({
      method: "GET",
      url: "/api/me",
      headers: { authorization: "Bearer " + ALICE },
    });
    expect(me.json()).toEqual({ principal: { id: "alice" } });

    const anonymous = await app.inject({ method: "GET", url: "/api/me" });
    expect(anonymous.statusCode).toBe(401);
    await app.close();
  });

  it("leaves the API open when no principal is configured, and reports none", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);
    const open = await app.inject({ method: "GET", url: "/api/agents" });
    expect(open.statusCode).toBe(200);
    expect((await app.inject({ method: "GET", url: "/api/auth" })).json()).toEqual({
      required: false,
    });
    expect((await app.inject({ method: "GET", url: "/api/me" })).json()).toEqual({
      principal: null,
    });
    await app.close();
  });

  it("preserves Fastify client error status codes", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);
    const malformed = await app.inject({
      method: "POST",
      url: "/api/agents",
      headers: { "content-type": "application/json" },
      payload: "{not-json",
    });
    expect(malformed.statusCode).toBe(400);

    const oversized = await app.inject({
      method: "POST",
      url: "/api/agents",
      headers: { "content-type": "application/json" },
      payload: JSON.stringify({ name: "x".repeat(1_100_000) }),
    });
    expect(oversized.statusCode).toBe(413);
    await app.close();
  });

  it("takes the approver from the credential and refuses a client-supplied actor", async () => {
    const calls: unknown[] = [];
    const recording = {
      listAgents: () => [],
      systemInfo: async () => ({}),
      resolveApproval: async (
        id: string,
        decision: string,
        principal: { id: string },
        reason: string,
      ) => {
        calls.push({ id, decision, principal, reason });
        return {
          approval: { id, status: "approved", resolvedBy: principal.id },
          continuationRun: null,
        };
      },
    } as unknown as AgentService;
    const app = await createApp(
      loadConfig({ NODE_ENV: "test", APP_PRINCIPALS: "alice:" + ALICE }),
      recording,
    );
    const approvalId = "11111111-1111-4111-8111-111111111111";
    const url = "/api/approvals/" + approvalId;
    const headers = { authorization: "Bearer " + ALICE };

    // A client still sending `actor` is rejected outright, not silently stripped:
    // stripping would hide the vulnerability rather than remove it.
    const spoofed = await app.inject({
      method: "POST",
      url,
      headers,
      payload: { decision: "approve", reason: "ok", actor: "someone-else" },
    });
    expect(spoofed.statusCode).toBe(400);
    expect(calls).toHaveLength(0);

    const accepted = await app.inject({
      method: "POST",
      url,
      headers,
      payload: { decision: "approve", reason: "npm registry is trusted" },
    });
    expect(accepted.statusCode).toBe(200);
    expect(calls).toEqual([
      {
        id: approvalId,
        decision: "approve",
        principal: { id: "alice" },
        reason: "npm registry is trusted",
      },
    ]);
    expect(accepted.json().approval.resolvedBy).toBe("alice");
    await app.close();
  });

  it("refuses an approval when no principal backs the request", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);
    const response = await app.inject({
      method: "POST",
      url: "/api/approvals/11111111-1111-4111-8111-111111111111",
      payload: { decision: "approve", reason: "ok" },
    });
    expect(response.statusCode).toBe(401);
    expect(response.json().error).toMatch(/APP_PRINCIPALS/);
    await app.close();
  });
});
