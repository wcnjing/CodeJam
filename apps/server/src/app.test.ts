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
});
