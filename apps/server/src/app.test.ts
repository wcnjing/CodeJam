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

  it("gates on the routed path, so a percent-encoded /api/ prefix cannot slip past", async () => {
    // find-my-way routes on decodeURI(path), so `/%61pi/agents` reaches the
    // `/api/agents` handler. A hook keyed on the raw URL string let that request
    // through unauthenticated — reading every agent, and DELETE purging the
    // audit evidence this product exists to protect.
    const app = await createApp(
      loadConfig({ NODE_ENV: "test", APP_PRINCIPALS: "alice:" + ALICE }),
      service,
    );
    const encoded = await app.inject({ method: "GET", url: "/%61pi/agents" });
    expect(encoded.statusCode).toBe(401);

    const encodedWithToken = await app.inject({
      method: "GET",
      url: "/%61pi/agents",
      headers: { authorization: "Bearer " + ALICE },
    });
    expect(encodedWithToken.statusCode).toBe(200);

    // An unmatched path has no routed path, so 404 handling is untouched.
    expect((await app.inject({ method: "GET", url: "/nope" })).statusCode).toBe(404);
    await app.close();
  });

  it("keeps /api/health and /api/auth open while principals are configured", async () => {
    // Without these exemptions the web UI could never discover that auth is
    // required, and the unlock screen would never render.
    const app = await createApp(
      loadConfig({ NODE_ENV: "test", APP_PRINCIPALS: "alice:" + ALICE }),
      service,
    );
    const health = await app.inject({ method: "GET", url: "/api/health" });
    expect(health.statusCode).toBe(200);

    const auth = await app.inject({ method: "GET", url: "/api/auth" });
    expect(auth.statusCode).toBe(200);
    expect(auth.json()).toEqual({ required: true });
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

    // Identity is checked before content, so a garbage id and a garbage body
    // still answer 401 rather than 400. A valid payload alone would not pin the
    // ordering: this is the assertion that keeps the guard ahead of the parse.
    const garbage = await app.inject({
      method: "POST",
      url: "/api/approvals/not-a-uuid",
      payload: { decision: "banana" },
    });
    expect(garbage.statusCode).toBe(401);
    expect(garbage.json().error).toMatch(/APP_PRINCIPALS/);
    await app.close();
  });

  it("serves the allowlist over HTTP and forwards the widening flag on approvals", async () => {
    const calls: unknown[] = [];
    const recording = {
      listAgents: () => [],
      systemInfo: async () => ({}),
      getAllowlist: () => ({ config: ["cfg.example.com"], overrides: [] }),
      addAllowlistHost: async (host: string) => {
        calls.push(["add", host]);
        return [host];
      },
      removeAllowlistHost: async (host: string) => {
        calls.push(["remove", host]);
        return [];
      },
      resolveApproval: async (
        id: string,
        decision: string,
        principal: { id: string },
        reason: string,
        allowlist?: boolean,
      ) => {
        calls.push(["resolve", id, decision, reason, allowlist]);
        return { approval: { id, status: "approved", resolvedBy: principal.id }, continuationRun: null };
      },
    } as unknown as AgentService;
    const app = await createApp(
      loadConfig({ NODE_ENV: "test", APP_PRINCIPALS: "alice:" + ALICE }),
      recording,
    );
    const headers = { authorization: "Bearer " + ALICE };

    // Allowlist reads are gated like every /api route.
    expect((await app.inject({ method: "GET", url: "/api/allowlist" })).statusCode).toBe(401);
    const listed = await app.inject({ method: "GET", url: "/api/allowlist", headers });
    expect(listed.statusCode).toBe(200);
    expect(listed.json()).toEqual({ config: ["cfg.example.com"], overrides: [] });

    // Add and remove; the body is strict, so a stray key is refused.
    const added = await app.inject({
      method: "POST",
      url: "/api/allowlist",
      headers,
      payload: { host: "docs.example.com" },
    });
    expect(added.statusCode).toBe(201);
    expect(added.json()).toEqual({ overrides: ["docs.example.com"] });
    expect(calls).toContainEqual(["add", "docs.example.com"]);

    const stray = await app.inject({
      method: "POST",
      url: "/api/allowlist",
      headers,
      payload: { host: "docs.example.com", actor: "someone-else" },
    });
    expect(stray.statusCode).toBe(400);

    const removed = await app.inject({
      method: "DELETE",
      url: "/api/allowlist/docs.example.com",
      headers,
    });
    expect(removed.statusCode).toBe(200);
    expect(calls).toContainEqual(["remove", "docs.example.com"]);

    // The optional widening flag reaches the service: true, false, and absent.
    const approvalId = "22222222-2222-4222-8222-222222222222";
    for (const payload of [
      { decision: "approve", reason: "trusted", allowlist: true },
      { decision: "approve", reason: "trusted", allowlist: false },
      { decision: "approve", reason: "trusted" },
    ]) {
      const resolved = await app.inject({
        method: "POST",
        url: "/api/approvals/" + approvalId,
        headers,
        payload,
      });
      expect(resolved.statusCode).toBe(200);
    }
    expect(calls).toContainEqual(["resolve", approvalId, "approve", "trusted", true]);
    expect(calls).toContainEqual(["resolve", approvalId, "approve", "trusted", false]);
    expect(calls).toContainEqual(["resolve", approvalId, "approve", "trusted", false]);
    await app.close();
  });
});
