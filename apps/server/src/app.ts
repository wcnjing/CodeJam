import cors from "@fastify/cors";
import fastifyStatic from "@fastify/static";
import Fastify, { type FastifyInstance } from "fastify";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { AppConfig } from "./config.js";
import { HttpError } from "./errors.js";
import type { AgentService } from "./agent-service.js";
import { buildEvaluationSummary } from "./evaluation-summary.js";
import type { Principal } from "./principals.js";

declare module "fastify" {
  interface FastifyRequest {
    /** Resolved from the presented credential. Never client-supplied. */
    principal: Principal | null;
  }
}

const agentIdParams = z.object({ id: z.string().uuid() });
const runIdParams = z.object({ id: z.string().uuid() });
const approvalIdParams = z.object({ id: z.string().uuid() });
// .strict() is load-bearing: Zod strips unknown keys by default, so a client
// still sending `actor` would be silently ignored — the hole hidden rather than
// closed. Strict mode fails the request and says the field is gone.
const approvalDecisionBody = z
  .object({
    decision: z.enum(["approve", "deny"]),
    // Required: the audit trail claims every decision records why, so enforce it.
    reason: z.string().trim().min(1).max(2000),
  })
  .strict();
const createAgentBody = z.object({
  name: z.string().trim().min(1).max(80),
  description: z.string().max(500).optional(),
  instructions: z.string().max(10_000).optional(),
});
const updateAgentBody = createAgentBody.partial().refine(
  (value) => Object.keys(value).length > 0,
  "At least one field is required",
);
const messageBody = z.object({
  content: z.string().trim().min(1).max(50_000),
});

export async function createApp(
  config: AppConfig,
  service: AgentService,
): Promise<FastifyInstance> {
  const app = Fastify({
    logger: {
      level: config.logLevel,
      redact: ["req.headers.authorization", "req.headers.cookie"],
    },
    bodyLimit: 1_048_576,
  });

  await app.register(cors, {
    origin:
      config.nodeEnv === "development"
        ? ["http://localhost:5173", "http://127.0.0.1:5173"]
        : false,
  });

  app.decorateRequest("principal", null);

  app.addHook("onRequest", async (request, reply) => {
    // Gate on the ROUTED path, not the raw URL. find-my-way matches on
    // decodeURI(path), so `/%61pi/agents` reaches the `/api/agents` handler
    // while its raw URL does not start with "/api/" — gating on the raw string
    // let an unauthenticated caller read and delete agents. routeOptions.url is
    // the route pattern (e.g. "/api/agents/:id") and is undefined when nothing
    // matched, which leaves 404 handling alone.
    const routePath = request.routeOptions?.url ?? "";
    if (
      !routePath.startsWith("/api/") ||
      routePath === "/api/health" ||
      routePath === "/api/auth"
    ) {
      return;
    }
    const header = request.headers.authorization ?? "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    request.principal = config.principals.resolve(token);
    // With no principals configured the API stays open, exactly as it was with
    // an empty APP_AUTH_TOKEN. Approvals refuse separately on a null principal,
    // so an unattributable decision is impossible either way.
    if (config.principals.size > 0 && !request.principal) {
      return reply.code(401).send({ error: "Authentication required" });
    }
  });

  app.get("/api/health", async () => ({
    ok: true,
    service: "volc-agent-launchpad",
  }));

  app.get("/api/auth", async () => ({ required: config.principals.size > 0 }));

  // Lets the UI name the principal it is deciding as. This cannot fold into
  // /api/auth, which is exempt from the hook and so has no principal to report.
  app.get("/api/me", async (request) => ({ principal: request.principal }));

  app.get("/api/system", async () => service.systemInfo());

  app.get("/api/agents", async () => ({ agents: service.listAgents() }));

  app.post("/api/agents", async (request, reply) => {
    const body = createAgentBody.parse(request.body);
    const agent = await service.createAgent(body);
    return reply.code(201).send({ agent });
  });

  app.get("/api/agents/:id", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { agent: service.getAgent(id) };
  });

  app.patch("/api/agents/:id", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    const body = updateAgentBody.parse(request.body);
    return { agent: await service.updateAgent(id, body) };
  });

  app.delete("/api/agents/:id", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return service.deleteAgent(id);
  });

  app.post("/api/agents/:id/start", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { agent: await service.startAgent(id) };
  });

  app.post("/api/agents/:id/stop", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { agent: await service.stopAgent(id) };
  });

  app.get("/api/agents/:id/messages", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { messages: service.getMessages(id) };
  });

  app.get("/api/agents/:id/runs", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { runs: service.getRuns(id) };
  });

  app.post("/api/agents/:id/messages", async (request, reply) => {
    const { id } = agentIdParams.parse(request.params);
    const body = messageBody.parse(request.body);
    const result = await service.sendMessage(id, body.content);
    return reply.code(202).send(result);
  });

  app.get("/api/agents/:id/policy-events", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { policyEvents: service.getPolicyEvents(id) };
  });

  app.get("/api/agents/:id/approvals", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { approvals: service.listApprovals(id) };
  });

  app.post("/api/approvals/:id", async (request, reply) => {
    // Identity before content: an unattributable decision is refused before the
    // approval id or the body is even considered.
    const principal = request.principal;
    if (!principal) {
      return reply.code(401).send({
        error:
          "Resolving an approval requires an authenticated principal. Set APP_PRINCIPALS " +
          "and present that principal's token.",
      });
    }
    const { id } = approvalIdParams.parse(request.params);
    const body = approvalDecisionBody.parse(request.body);
    const result = await service.resolveApproval(id, body.decision, principal, body.reason);
    return reply.code(200).send(result);
  });

  app.get("/api/evaluation", async () => buildEvaluationSummary());

  app.get("/api/runs/:id", async (request) => {
    const { id } = runIdParams.parse(request.params);
    return { run: service.getRun(id) };
  });

  if (config.nodeEnv === "production") {
    const webRoot = fileURLToPath(new URL("../../web/dist", import.meta.url));
    await app.register(fastifyStatic, {
      root: webRoot,
      prefix: "/",
    });
    app.setNotFoundHandler((request, reply) => {
      if (request.url.startsWith("/api/")) {
        return reply.code(404).send({ error: "API route not found" });
      }
      return reply.sendFile("index.html");
    });
  }

  app.setErrorHandler((error, request, reply) => {
    const appError = error instanceof Error ? error : new Error(String(error));
    const validationError = error instanceof z.ZodError;
    const frameworkStatus =
      typeof (error as { statusCode?: unknown }).statusCode === "number"
        ? (error as { statusCode: number }).statusCode
        : null;
    const statusCode =
      error instanceof HttpError
        ? error.statusCode
        : validationError
          ? 400
          : frameworkStatus && frameworkStatus >= 400 && frameworkStatus <= 599
            ? frameworkStatus
            : 500;
    if (statusCode >= 500) {
      request.log.error(appError);
    }
    return reply.code(statusCode).send({
      error: appError.message,
      ...(validationError ? { details: error.issues } : {}),
    });
  });

  return app;
}
