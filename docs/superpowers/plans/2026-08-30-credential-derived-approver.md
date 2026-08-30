# Credential-Derived Approver Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `approval.resolvedBy` derive from the credential presented on the request, so a client can never assert who approved a held run.

**Architecture:** A new `PrincipalRegistry` parses `APP_PRINCIPALS` (`id:token` pairs) into a map of SHA-256 token digests to named principals. The Fastify `onRequest` hook resolves the bearer to a `Principal` and decorates the request with it; `POST /api/approvals/:id` refuses outright when no principal backs the request, drops `actor` from its body schema, and passes the resolved principal to `AgentService.resolveApproval`. The shared `APP_AUTH_TOKEN` is removed entirely, so no unattributable credential survives.

**Tech Stack:** TypeScript (ESM, NodeNext), Fastify 5, Zod, Vitest, React + Vite, Terraform.

**Spec:** `docs/superpowers/specs/2026-08-30-credential-derived-approver-design.md`

## Global Constraints

- Imports of local modules use the `.js` extension (NodeNext ESM), e.g. `./principals.js`.
- Server tests run with `npm test` from the repo root (delegates to `vitest run` in `apps/server`). A single file: `npm test -w @launchpad/server -- src/principals.test.ts`.
- Full gate before the final commit: `npm run check` (typecheck + test + build).
- The web workspace has no test runner; verify it with `npm run typecheck` and `npm run build`.
- Principal id charset: `^[A-Za-z0-9._@-]{1,64}$`. Token charset: `^[A-Za-z0-9._~-]{1,128}$`.
- Minimum token length: 8 by default, 24 for a non-loopback production server. Tokens beginning `replace-` are rejected in every environment.
- Loopback hosts are exactly `127.0.0.1`, `::1`, `localhost` (already defined in `config.ts`).
- Error strings shown to operators must never echo a token value.
- Commit messages end with `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.

---

### Task 1: PrincipalRegistry

A pure module with no Fastify or AgentService dependency, so parsing and resolution are testable on their own.

**Files:**
- Create: `apps/server/src/principals.ts`
- Test: `apps/server/src/principals.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `export interface Principal { id: string }`
  - `export interface PrincipalRegistryOptions { minTokenLength?: number }`
  - `export class PrincipalRegistry` with `static parse(raw: string, options?: PrincipalRegistryOptions): PrincipalRegistry`, `get size(): number`, `resolve(token: string): Principal | null`

- [ ] **Step 1: Write the failing test**

Create `apps/server/src/principals.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { PrincipalRegistry } from "./principals.js";

const ALICE = "tok_alice_0123456789abcdef";
const BOB = "tok_bob_0123456789abcdef";

describe("PrincipalRegistry", () => {
  it("resolves a configured token to its principal id", () => {
    const registry = PrincipalRegistry.parse("alice:" + ALICE + ",bob:" + BOB);
    expect(registry.size).toBe(2);
    expect(registry.resolve(ALICE)).toEqual({ id: "alice" });
    expect(registry.resolve(BOB)).toEqual({ id: "bob" });
  });

  it("returns null for an unknown or empty token", () => {
    const registry = PrincipalRegistry.parse("alice:" + ALICE);
    expect(registry.resolve("tok_nope_0123456789abcdef")).toBeNull();
    expect(registry.resolve("")).toBeNull();
  });

  it("treats an empty setting as no principals configured", () => {
    const registry = PrincipalRegistry.parse("");
    expect(registry.size).toBe(0);
    expect(registry.resolve(ALICE)).toBeNull();
  });

  it("tolerates surrounding whitespace between entries", () => {
    const registry = PrincipalRegistry.parse(" alice:" + ALICE + " , bob:" + BOB + " ");
    expect(registry.resolve(ALICE)).toEqual({ id: "alice" });
    expect(registry.resolve(BOB)).toEqual({ id: "bob" });
  });

  it("rejects duplicate ids so two humans cannot share one name", () => {
    expect(() => PrincipalRegistry.parse("alice:" + ALICE + ",alice:" + BOB)).toThrow(
      /duplicate id/i,
    );
  });

  it("rejects one token shared by two ids as ambiguous identity", () => {
    expect(() => PrincipalRegistry.parse("alice:" + ALICE + ",bob:" + ALICE)).toThrow(
      /ambiguous/i,
    );
  });

  it("rejects malformed entries", () => {
    expect(() => PrincipalRegistry.parse("alice")).toThrow(/id:token/i);
    expect(() => PrincipalRegistry.parse(":" + ALICE)).toThrow(/id/i);
    expect(() => PrincipalRegistry.parse("alice:")).toThrow(/token/i);
    expect(() => PrincipalRegistry.parse("alice:has spaces")).toThrow(/URL-safe/i);
    expect(() => PrincipalRegistry.parse("not a valid id:" + ALICE)).toThrow(/id/i);
  });

  it("enforces the caller's minimum token length", () => {
    expect(() => PrincipalRegistry.parse("alice:tok_short", { minTokenLength: 24 })).toThrow(
      /at least 24/i,
    );
    expect(PrincipalRegistry.parse("alice:" + ALICE, { minTokenLength: 24 }).size).toBe(1);
  });

  it("rejects a placeholder token in any environment", () => {
    expect(() => PrincipalRegistry.parse("alice:replace-with-a-real-token")).toThrow(
      /placeholder/i,
    );
  });

  it("never echoes a token in an error message", () => {
    // A bare token with no id is the likeliest paste mistake; the message must
    // point at the entry position, not print the secret back into the logs.
    expect(() => PrincipalRegistry.parse(ALICE)).toThrow(
      expect.objectContaining({ message: expect.not.stringContaining(ALICE) }),
    );
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test -w @launchpad/server -- src/principals.test.ts`
Expected: FAIL — `Failed to resolve import "./principals.js"`.

- [ ] **Step 3: Write the implementation**

Create `apps/server/src/principals.ts`:

```ts
import { createHash } from "node:crypto";

/** An authenticated caller. The id is what lands in the audit record. */
export interface Principal {
  id: string;
}

export interface PrincipalRegistryOptions {
  /** Minimum token length. A remote production server raises this to 24. */
  minTokenLength?: number;
}

const ID_PATTERN = /^[A-Za-z0-9._@-]{1,64}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9._~-]{1,128}$/;

function digestOf(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/**
 * Maps bearer tokens to named principals.
 *
 * Tokens are retained only as SHA-256 digests, so resolution is a map lookup on
 * the digest rather than a comparison loop: there is no secret-dependent
 * comparison, and the work does not grow with the number of principals
 * configured. Nothing here reads a token back out, which is also why token
 * length is validated during parsing rather than by the caller afterwards.
 */
export class PrincipalRegistry {
  private constructor(private readonly byTokenDigest: Map<string, Principal>) {}

  static parse(raw: string, options: PrincipalRegistryOptions = {}): PrincipalRegistry {
    const minTokenLength = options.minTokenLength ?? 8;
    const byTokenDigest = new Map<string, Principal>();
    const seenIds = new Set<string>();
    const entries = raw
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);

    entries.forEach((entry, index) => {
      const position = "entry " + (index + 1) + " of APP_PRINCIPALS";
      const separator = entry.indexOf(":");
      if (separator < 0) {
        // Deliberately does not echo `entry`: a missing id usually means someone
        // pasted a bare token, and the message would leak it.
        throw new Error(position + ' must look like "id:token".');
      }
      const id = entry.slice(0, separator).trim();
      const token = entry.slice(separator + 1).trim();
      if (!ID_PATTERN.test(id)) {
        throw new Error(
          position + " has an invalid id; use 1-64 characters of [A-Za-z0-9._@-].",
        );
      }
      if (!TOKEN_PATTERN.test(token)) {
        throw new Error(
          "The token for " + id + " must use 1-128 URL-safe characters ([A-Za-z0-9._~-]).",
        );
      }
      if (token.length < minTokenLength) {
        throw new Error(
          "The token for " + id + " must contain at least " + minTokenLength + " characters.",
        );
      }
      if (token.startsWith("replace-")) {
        throw new Error("The token for " + id + " is still the placeholder value.");
      }
      if (seenIds.has(id)) {
        throw new Error(
          "APP_PRINCIPALS contains duplicate id " + id + "; each principal needs its own name.",
        );
      }
      const tokenDigest = digestOf(token);
      if (byTokenDigest.has(tokenDigest)) {
        throw new Error(
          "APP_PRINCIPALS reuses one token across ids, which makes identity ambiguous.",
        );
      }
      seenIds.add(id);
      byTokenDigest.set(tokenDigest, { id });
    });

    return new PrincipalRegistry(byTokenDigest);
  }

  /** How many principals are configured. Zero means authentication is off. */
  get size(): number {
    return this.byTokenDigest.size;
  }

  resolve(token: string): Principal | null {
    if (!token) return null;
    const principal = this.byTokenDigest.get(digestOf(token));
    return principal ? { ...principal } : null;
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm test -w @launchpad/server -- src/principals.test.ts`
Expected: PASS, 10 tests.

- [ ] **Step 5: Commit**

```bash
git add apps/server/src/principals.ts apps/server/src/principals.test.ts
git commit -m "feat: add PrincipalRegistry mapping bearer tokens to named principals

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: Authentication yields a principal

Config and the HTTP boundary move together: the moment `config.authToken` is removed, `app.ts` must stop reading it, so splitting these would leave a red build between commits.

**Files:**
- Modify: `apps/server/src/config.ts:36-40` (drop `APP_AUTH_TOKEN` from the schema), `:66-76` (loadConfig guards), `:98` (returned config)
- Modify: `apps/server/src/app.ts:1-10` (imports), `:52-70` (auth hook), `:79` (`/api/auth`)
- Modify: `apps/server/src/app.test.ts:11-26`
- Modify: `apps/server/src/config-policy.test.ts`

**Interfaces:**
- Consumes: `PrincipalRegistry`, `Principal` from Task 1.
- Produces:
  - `AppConfig.principals: PrincipalRegistry` (and `AppConfig.authToken` no longer exists)
  - `FastifyRequest.principal: Principal | null` on every request
  - `GET /api/me` → `{ principal: { id: string } | null }`

- [ ] **Step 1: Write the failing tests**

Replace the first test in `apps/server/src/app.test.ts` (currently `"protects API routes with the configured shared token"`, lines 12-26) with these three, keeping the existing `"preserves Fastify client error status codes"` test and the file's existing imports and `service` stub unchanged:

```ts
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
```

Append to `apps/server/src/config-policy.test.ts`:

```ts
describe("credential configuration", () => {
  it("refuses to start when the retired APP_AUTH_TOKEN is still set", () => {
    expect(() => loadConfig({ ...base, APP_AUTH_TOKEN: "a-strong-legacy-token" })).toThrow(
      /APP_PRINCIPALS/,
    );
  });

  it("requires at least one principal on a non-loopback production server", () => {
    expect(() => loadConfig({ ...base, NODE_ENV: "production", HOST: "0.0.0.0" })).toThrow(
      /APP_PRINCIPALS/,
    );
  });

  it("requires production tokens of at least 24 characters", () => {
    expect(() =>
      loadConfig({
        ...base,
        NODE_ENV: "production",
        HOST: "0.0.0.0",
        APP_PRINCIPALS: "alice:tok_short",
      }),
    ).toThrow(/at least 24/);
  });

  it("allows a loopback development server with no principals", () => {
    expect(loadConfig(base).principals.size).toBe(0);
  });

  it("resolves a configured token through the parsed config", () => {
    const config = loadConfig({ ...base, APP_PRINCIPALS: "alice:tok_alice_0123456789abcdef" });
    expect(config.principals.resolve("tok_alice_0123456789abcdef")).toEqual({ id: "alice" });
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npm test -w @launchpad/server -- src/app.test.ts src/config-policy.test.ts`
Expected: FAIL — `/api/me` returns 404, and `config.principals` is undefined.

- [ ] **Step 3: Update the config**

In `apps/server/src/config.ts`, add the import beneath the existing `REVIEWABLE_RULES` import:

```ts
import { PrincipalRegistry } from "./principals.js";
```

Delete the `APP_AUTH_TOKEN` entry from `envSchema` (lines 36-40) and add in its place:

```ts
  // Named approver credentials: comma-separated id:token pairs. The id is what
  // an approval records, so it must come from here and never from a request body.
  APP_PRINCIPALS: z.string().default(""),
```

Replace the body of `loadConfig` from its first line through the production check (lines 66-76) with:

```ts
export function loadConfig(environment: NodeJS.ProcessEnv = process.env) {
  if ((environment.APP_AUTH_TOKEN ?? "").trim().length > 0) {
    throw new Error(
      "APP_AUTH_TOKEN has been replaced by APP_PRINCIPALS. A shared token cannot be " +
        "attributed to a person, so approvals no longer accept one. Set " +
        'APP_PRINCIPALS="alice:<token>,bob:<token>" and remove APP_AUTH_TOKEN.',
    );
  }
  const env = envSchema.parse(environment);
  const loopbackHosts = new Set(["127.0.0.1", "::1", "localhost"]);
  const remoteProduction = env.NODE_ENV === "production" && !loopbackHosts.has(env.HOST);
  const principals = PrincipalRegistry.parse(env.APP_PRINCIPALS, {
    minTokenLength: remoteProduction ? 24 : 8,
  });
  if (remoteProduction && principals.size === 0) {
    throw new Error(
      "APP_PRINCIPALS must configure at least one principal for a non-loopback production server",
    );
  }
```

Delete the `const authToken = ...` line, and in the returned object replace `authToken,` with `principals,`.

- [ ] **Step 4: Update the HTTP boundary**

In `apps/server/src/app.ts`, delete `import { timingSafeEqual } from "node:crypto";` and add:

```ts
import type { Principal } from "./principals.js";

declare module "fastify" {
  interface FastifyRequest {
    /** Resolved from the presented credential. Never client-supplied. */
    principal: Principal | null;
  }
}
```

Replace the whole `app.addHook("onRequest", ...)` block (lines 52-70) with:

```ts
  app.decorateRequest("principal", null);

  app.addHook("onRequest", async (request, reply) => {
    if (
      !request.url.startsWith("/api/") ||
      request.url === "/api/health" ||
      request.url === "/api/auth"
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
```

Replace the `/api/auth` route (line 79) and add `/api/me` after it:

```ts
  app.get("/api/auth", async () => ({ required: config.principals.size > 0 }));

  // Lets the UI name the principal it is deciding as. This cannot fold into
  // /api/auth, which is exempt from the hook and so has no principal to report.
  app.get("/api/me", async (request) => ({ principal: request.principal }));
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `npm test -w @launchpad/server -- src/app.test.ts src/config-policy.test.ts`
Expected: PASS.

- [ ] **Step 6: Typecheck**

Run: `npm run typecheck`
Expected: clean. `config.authToken` was read in exactly three places, all in `app.ts`
(the two hook lines and `/api/auth`), and all three are replaced above. Confirm with
`grep -rn "config.authToken" apps/server/src` returning nothing.

Leave `apps/web/src/api.ts:20-23` alone: its module-level `authToken` is the browser's
copy of whatever token the user pasted, which is now a principal's token. Same name,
different thing.

- [ ] **Step 7: Commit**

```bash
git add apps/server/src/config.ts apps/server/src/app.ts apps/server/src/app.test.ts apps/server/src/config-policy.test.ts
git commit -m "feat: authenticate callers as named principals, retire APP_AUTH_TOKEN

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: The approver comes from the credential

The change the whole plan exists for.

**Files:**
- Modify: `apps/server/src/app.ts:15-20` (body schema), `:144-153` (route)
- Modify: `apps/server/src/agent-service.ts:195-208` (signature and guards), `:218`, `:268`
- Modify: `apps/server/src/types.ts:95-96` (doc comment)
- Modify: `apps/server/src/approval.test.ts` (call sites)
- Test: `apps/server/src/app.test.ts`

**Interfaces:**
- Consumes: `Principal` and `request.principal` from Task 2.
- Produces: `AgentService.resolveApproval(id: string, decision: "approve" | "deny", principal: Principal, reason: string)`; request body `{ decision, reason }` only, strict.

- [ ] **Step 1: Write the failing tests**

Add to `apps/server/src/app.test.ts` inside the existing `describe("HTTP boundary")`:

```ts
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npm test -w @launchpad/server -- src/app.test.ts`
Expected: FAIL — the spoofed request returns 200 because Zod strips `actor`, and the unauthenticated approval reaches the service instead of 401.

- [ ] **Step 3: Tighten the endpoint**

In `apps/server/src/app.ts`, replace `approvalDecisionBody` (lines 15-20) with:

```ts
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
```

Replace the route (lines 144-153) with:

```ts
  app.post("/api/approvals/:id", async (request, reply) => {
    const { id } = approvalIdParams.parse(request.params);
    // Identity before content: an unattributable decision is refused before the
    // body is even considered.
    const principal = request.principal;
    if (!principal) {
      return reply.code(401).send({
        error:
          "Resolving an approval requires an authenticated principal. Set APP_PRINCIPALS " +
          "and present that principal's token.",
      });
    }
    const body = approvalDecisionBody.parse(request.body);
    const result = await service.resolveApproval(id, body.decision, principal, body.reason);
    return reply.code(200).send(result);
  });
```

- [ ] **Step 4: Update the service**

In `apps/server/src/agent-service.ts`, add to the imports:

```ts
import type { Principal } from "./principals.js";
```

Replace the signature and the two guards (lines 195-208) with:

```ts
  async resolveApproval(
    id: string,
    decision: "approve" | "deny",
    principal: Principal,
    reason: string,
  ): Promise<{ approval: ApprovalRequest; continuationRun: AgentRun | null }> {
    // No "approver name required" guard: the caller is a resolved Principal, so
    // an anonymous decision is unrepresentable rather than merely rejected.
    const trimmedReason = reason.trim();
    if (!trimmedReason) {
      throw new HttpError(400, "A reason is required so every decision records why");
    }
```

Change both assignments (lines 218 and 268) from `approval.resolvedBy = trimmedActor;` to:

```ts
        approval.resolvedBy = principal.id;
```

- [ ] **Step 5: Update the type comment**

In `apps/server/src/types.ts`, replace lines 95-96:

```ts
  /**
   * Id of the authenticated principal that resolved it, derived from the
   * credential presented on the request. Never client-supplied.
   */
  resolvedBy: string | null;
```

- [ ] **Step 6: Update the service tests**

In `apps/server/src/approval.test.ts`, add to the imports:

```ts
import type { Principal } from "./principals.js";
```

Add below the `dirs` declaration:

```ts
const ALICE: Principal = { id: "ops-alice" };
const BOB: Principal = { id: "ops-bob" };
const OPS: Principal = { id: "ops" };
```

Replace every string actor argument with the matching constant: `"ops-alice"` → `ALICE`, `"ops-bob"` → `BOB`, `"ops"` → `OPS`, `"ops-a"` → `ALICE`, `"ops-b"` → `BOB`. The `resolvedBy` assertions keep their existing string values (`"ops-alice"`, `"ops-bob"`), which now come from the principal ids.

Delete the whole `it("requires a named approver", ...)` test (lines 255-266). It asserted a guard that no longer exists; its replacement is the endpoint-level 401 test written in Step 1.

- [ ] **Step 7: Run the full server suite**

Run: `npm test`
Expected: PASS, with the approval suite one test shorter.

- [ ] **Step 8: Commit**

```bash
git add apps/server/src/app.ts apps/server/src/agent-service.ts apps/server/src/types.ts apps/server/src/approval.test.ts apps/server/src/app.test.ts
git commit -m "fix: derive the approver from the credential, not the request body

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: Web UI decides as the authenticated principal

**Files:**
- Modify: `apps/web/src/api.ts:43-44` (add `me`), `:94-103` (`resolveApproval`)
- Modify: `apps/web/src/types.ts:83` (comment), and add a `Principal` type
- Modify: `apps/web/src/App.tsx:241`, `:322-324`, `:480-497`, `:990-1027`

**Interfaces:**
- Consumes: `GET /api/me` from Task 2; the `{ decision, reason }` body from Task 3.
- Produces: no server-facing interface.

- [ ] **Step 1: Add the client call**

In `apps/web/src/types.ts`, add above `ApprovalRequest`:

```ts
export interface Principal {
  id: string;
}
```

and replace line 83 with:

```ts
  /** Authenticated principal that resolved it. Never client-supplied. */
  resolvedBy: string | null;
```

In `apps/web/src/api.ts`, add `Principal` to the type import list, add a `me` call after `auth`:

```ts
  me: () => request<{ principal: Principal | null }>("/api/me"),
```

and replace `resolveApproval` (lines 94-103) with:

```ts
  resolveApproval: (
    approvalId: string,
    decision: "approve" | "deny",
    reason: string,
  ) =>
    request<{ approval: ApprovalRequest; continuationRun: AgentRun | null }>(
      "/api/approvals/" + approvalId,
      { method: "POST", body: JSON.stringify({ decision, reason }) },
    ),
```

- [ ] **Step 2: Hold the principal in App state**

In `apps/web/src/App.tsx`, add `Principal` to the type import from `./types`, then replace line 241:

```tsx
  const [principal, setPrincipal] = useState<Principal | null>(null);
```

Replace `bootstrap` (lines 322-324):

```tsx
  const bootstrap = useCallback(async () => {
    await Promise.all([
      refreshAgents(),
      api.system().then(setSystem),
      api.me().then(({ principal: current }) => setPrincipal(current)),
    ]);
  }, [refreshAgents]);
```

In the `resolveApproval` handler (around line 488), drop the actor argument:

```tsx
      const result = await api.resolveApproval(
        approval.id,
        decision,
        approvalReason.trim(),
      );
```

- [ ] **Step 3: Replace the approver input with the resolved identity**

Replace the `approval-controls` and `approval-actions` blocks (lines 990-1027) with:

```tsx
                    <div className="approval-controls">
                      <label>
                        Reason
                        <input
                          value={approvalReason}
                          onChange={(event) => setApprovalReason(event.target.value)}
                          placeholder="why you approve or deny"
                        />
                      </label>
                    </div>
                    <div className="approval-actions">
                      <button
                        className="button button-primary"
                        disabled={busy || !principal || !approvalReason.trim()}
                        onClick={() => resolveApproval(pendingApproval, "approve")}
                      >
                        {principal ? "Approve as " + principal.id : "Approve & resume"}
                      </button>
                      <button
                        className="button button-danger"
                        disabled={busy || !principal || !approvalReason.trim()}
                        onClick={() => resolveApproval(pendingApproval, "deny")}
                      >
                        {principal ? "Deny as " + principal.id : "Deny"}
                      </button>
                      {!principal && (
                        <span className="policy-note">
                          Deciding requires an authenticated principal. Set APP_PRINCIPALS
                          and unlock with that principal&apos;s token.
                        </span>
                      )}
                      {principal && !approvalReason.trim() && (
                        <span className="policy-note">A reason is required to decide.</span>
                      )}
                    </div>
```

- [ ] **Step 4: Verify the web build**

Run: `npm run typecheck && npm run build`
Expected: clean. Then run `grep -rni "approver" apps/web/src`.
Expected: no matches. A hit means the state hook, the input, or a stale reference survived.

- [ ] **Step 5: Commit**

```bash
git add apps/web/src/App.tsx apps/web/src/api.ts apps/web/src/types.ts
git commit -m "feat(web): decide approvals as the authenticated principal

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 5: Configuration, deploy path, and documentation

Terraform must land with this change: left as it is, it injects `APP_AUTH_TOKEN` and every cloud deploy fails the new startup check.

**Files:**
- Modify: `.env.example:6-8`
- Modify: `README.md:323`, `:448`, `:511`
- Modify: `docs/DEPLOYMENT.md:100`, `:113-115`, `:127`
- Modify: `docs/ARCHITECTURE.md:26-28`
- Modify: `docs/THREAT_MODEL.md:118-119`
- Modify: `docs/OPERATIONAL_GOVERNANCE.md:46-49`
- Modify: `SECURITY.md:26`
- Modify: `deploy/volcengine/main.tf:37`, `deploy/volcengine/variables.tf:68-75`, `scripts/deploy-volcengine.sh:27-33`

**Interfaces:**
- Consumes: `APP_PRINCIPALS` from Task 2.
- Produces: nothing code-facing.

- [ ] **Step 1: Update `.env.example`**

Replace lines 6-8:

```dotenv
# Named approver credentials: comma-separated id:token pairs. The id is what an
# approval records as its approver, so give each person their own token and use
# 24+ random characters whenever the server listens beyond loopback. Unlock the
# browser with the token of the person deciding. Leave empty for a loopback demo,
# where the API is open but nothing can be approved.
APP_PRINCIPALS=
```

- [ ] **Step 2: Update the README**

Line 323 — replace `and requires a named approver + reason before it can continue or be denied.` with:

```markdown
and requires an authenticated approver + reason before it can continue or be denied.
The approver is taken from the credential on the request, so it cannot be typed in.
```

Line 448 — replace `APP_AUTH_TOKEN=replace-with-at-least-24-random-characters` with:

```dotenv
APP_PRINCIPALS=alice:replace-with-24-plus-random-characters
```

Line 511 — replace the table row with:

```markdown
| `APP_PRINCIPALS` | Empty on loopback | Comma-separated `id:token` approver credentials. The id is recorded as the approver; required to approve anything, and required outright when the server listens beyond loopback. |
```

- [ ] **Step 3: Update DEPLOYMENT.md**

Line 100 — replace `APP_AUTH_TOKEN=the-random-token-generated-above` with:

```dotenv
APP_PRINCIPALS=alice:the-random-token-generated-above
```

Lines 113-115 — replace the export and curl with:

```bash
export SENTINEL_TOKEN=the-token-you-configured-for-your-principal
curl -H "Authorization: Bearer $SENTINEL_TOKEN" \
```

Line 127 — replace with:

```markdown
- Add HTTPS before sending principal tokens across an untrusted network.
```

- [ ] **Step 4: Update ARCHITECTURE.md**

Replace lines 26-28 with:

```markdown
Validates requests, authenticates callers as named principals from
`APP_PRINCIPALS`, and serves the compiled Web UI. The credential establishes
identity — the id it resolves to is what an approval records — but not
authorization: every configured principal may do everything.
```

- [ ] **Step 5: Update THREAT_MODEL.md**

Replace lines 118-119 with:

```markdown
- **Any principal may approve anything.** `resolvedBy` is now an authenticated
  principal derived from the credential and cannot be asserted by a client, but
  authentication is not authorization: there are no roles, and nothing stops the
  principal behind a held run from approving it. Four-eyes needs runs attributed
  to a requesting principal, which the store does not record.
- **The principal registry is static.** Adding, rotating, or revoking a
  credential is an environment change plus a restart.
```

- [ ] **Step 6: Update OPERATIONAL_GOVERNANCE.md**

Replace gap 3 (lines 46-49) with:

```markdown
3. **Authenticated, not authorized.** "Approver" is now an authenticated
   principal resolved from the credential (`APP_PRINCIPALS`), so a decision can
   no longer be recorded under a name the decider simply typed. What remains is
   authorization: every principal may approve every held run, including one its
   own request caused, and the registry is static — no roles, no rotation, no
   segregation of duties.
```

- [ ] **Step 7: Update SECURITY.md**

Line 26 — replace with:

```markdown
- Use a scoped, revocable Ark key and a unique token per principal in `APP_PRINCIPALS`.
```

- [ ] **Step 8: Update the deploy path**

`deploy/volcengine/main.tf:37` — replace with:

```hcl
    "APP_PRINCIPALS=${var.app_principals}",
```

`deploy/volcengine/variables.tf:68-75` — replace the `app_auth_token` variable with:

```hcl
variable "app_principals" {
  description = "Comma-separated id:token approver credentials. Supplied through TF_VAR_app_principals."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[A-Za-z0-9._@-]{1,64}:[A-Za-z0-9._~-]{24,128}(,[A-Za-z0-9._@-]{1,64}:[A-Za-z0-9._~-]{24,128})*$", var.app_principals)) && !strcontains(var.app_principals, ":replace-")
    error_message = "app_principals must be one or more id:token pairs with 24-128 URL-safe, non-placeholder token characters."
  }
}
```

`deploy/volcengine/terraform.tfvars.example` needs no change: it never carried the token,
and it should not carry principal credentials either — they arrive through
`TF_VAR_app_principals`, which is why the variable is `sensitive = true`.

`scripts/deploy-volcengine.sh:27-33` — replace with:

```bash
if [[ "${ARK_API_KEY:-}" == "" || "${ARK_MODEL:-}" == "" || "${APP_PRINCIPALS:-}" == "" ]]; then
  echo "ARK_API_KEY, ARK_MODEL and APP_PRINCIPALS are required in .env.production." >&2
  exit 1
fi

export TF_VAR_ark_api_key="$ARK_API_KEY"
export TF_VAR_app_principals="$APP_PRINCIPALS"
```

- [ ] **Step 9: Verify nothing references the retired variable**

Run:

```bash
grep -rn "APP_AUTH_TOKEN\|app_auth_token" --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.worktrees --exclude-dir=graphify-out .
```

Expected: matches only inside `docs/superpowers/` (the spec and this plan, which describe the migration on purpose). Any other hit is an unfinished edit.

- [ ] **Step 10: Run the full gate**

Run: `npm run check`
Expected: typecheck, tests, and build all pass.

- [ ] **Step 11: Commit**

```bash
git add .env.example README.md SECURITY.md docs/ARCHITECTURE.md docs/DEPLOYMENT.md docs/THREAT_MODEL.md docs/OPERATIONAL_GOVERNANCE.md deploy/volcengine/main.tf deploy/volcengine/variables.tf scripts/deploy-volcengine.sh
git commit -m "docs: replace the shared token with named approver principals

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Manual verification

After Task 5, confirm the change end to end rather than trusting the suite alone.

- [ ] Add `APP_PRINCIPALS=alice:tok_local_dev_at_least_24_chars_ok` to `.env`, start with `npm run dev`, and unlock the UI with that token.
- [ ] Trigger a held run (a prompt that reaches a non-allowlisted host), then confirm the approval card shows "Approve as alice" with no name field.
- [ ] Approve with a reason and confirm the resolved card reads "Approval approved by alice".
- [ ] From a shell, confirm a spoof is refused:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:3000/api/approvals/$APPROVAL_ID \
  -H "Authorization: Bearer tok_local_dev_at_least_24_chars_ok" \
  -H 'Content-Type: application/json' \
  -d '{"decision":"approve","reason":"spoof","actor":"someone-else"}'
```

Expected: `400`.
