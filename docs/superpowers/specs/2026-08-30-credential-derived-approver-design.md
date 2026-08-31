# Approver identity derives from the credential

Status: approved for planning
Date: 2026-08-30

## Why

`POST /api/approvals/:id` accepts `actor` as free text (`app.ts:17`, `app.ts:150`) behind a
single shared bearer token (`app.ts:52-70`). Whatever the client types becomes
`approval.resolvedBy` (`agent-service.ts:218`). `types.ts:95` already concedes the
problem in a comment: "Named human who resolved it. No real identity in this POC — a
label."

For a governance product this makes the central audit claim unfalsifiable. Anyone
holding the one token can resolve any held run under any name, including a colleague's.
The record and the reality can differ with no way to tell from the store. This spec
makes the approver's identity derive from the presented credential so that the client
can no longer assert it.

Precisely what this does and does not buy, so the docs cannot overclaim:

- **Buys:** `resolvedBy` is an authenticated principal id, always, with no client-supplied
  path to it. Two different humans produce two different, non-forgeable audit records.
- **Does not buy:** authorization. Every configured principal may approve anything,
  including a run it triggered. Authentic is not authorized; the docs must say so.

## Decisions taken during brainstorming

1. **Identity source:** a static named-token registry in the environment. Not a user
   store, not an external IdP — no new dependencies, no runtime-issued secrets, and a
   two-approver demo needs only an env var.
2. **No principal, no approval:** an approval is refused (401) unless the bearer resolves
   to a configured principal, in every environment including local dev. No reserved
   sentinel identity exists, so no resolved approval can ever lack a real principal.
3. **Full replacement:** `APP_AUTH_TOKEN` is removed rather than kept alongside. Leaving
   an unattributable credential that can still start agents, send messages, and delete
   them invites the same criticism one layer over.

## Scope

In scope: `config.ts`, a new `principals.ts`, `app.ts`, `agent-service.ts`, `types.ts`;
web `App.tsx`, `api.ts`, `types.ts`; `app.test.ts`, `approval.test.ts`,
`config-policy.test.ts`, a new `principals.test.ts`; `.env.example`; `README.md`,
`docs/DEPLOYMENT.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`,
`docs/OPERATIONAL_GOVERNANCE.md`, `SECURITY.md`; and the deploy path —
`deploy/volcengine/main.tf`, `deploy/volcengine/variables.tf`,
`deploy/volcengine/terraform.tfvars.example`, `scripts/deploy-volcengine.sh`.

Out of scope, and named in the docs as the remaining gap rather than quietly left:

- **Segregation of duties / four-eyes.** Barring the principal who caused a run from
  approving it requires attributing runs to a requesting principal; nothing in the store
  does that today (`AgentRun` has no actor field).
- **Roles and permissions.** Every configured principal may approve every held run.
- **Runtime token issuance, rotation, and revocation.** The registry is static; changing
  it is an env change plus a restart.
- **Access control on the audit store**, and `deleteAgent()` purging `policyEvents` and
  `approvals`. Tracked separately.

## Data model

```ts
/** An authenticated caller. The id is what lands in the audit record. */
export interface Principal {
  id: string;
}
```

`ApprovalRequest.resolvedBy` keeps its `string | null` type; only its provenance and its
doc comment change:

```ts
/**
 * Id of the authenticated principal that resolved it, derived from the credential
 * presented on the request. Never client-supplied.
 */
resolvedBy: string | null;
```

## Config: `APP_PRINCIPALS`

Grammar — comma-separated `id:token` pairs. `:` is an unambiguous separator because the
token charset is URL-safe and therefore already excludes it.

```dotenv
APP_PRINCIPALS=alice:tok_alpha_at_least_24_chars,bob:tok_beta_at_least_24_chars
```

| Rule | Behaviour |
| --- | --- |
| id charset | `^[A-Za-z0-9._@-]{1,64}$` — permits `alice` and `alice@example.com` |
| token charset | `^[A-Za-z0-9._~-]{1,128}$`, matching today's URL-safe token rule. Charset and length are two layers: the pattern caps the length, and the minimum is enforced separately against `minTokenLength` (8 by default, raised to 24 for non-loopback production) so a caller can lift the floor without a second regex |
| malformed entry (no `:`, empty id, empty token) | throw at startup |
| duplicate id | throw — two humans behind one name defeats the point |
| duplicate token across ids | throw — ambiguous identity is worse than no identity |
| `APP_AUTH_TOKEN` present in the environment | throw with a migration message naming `APP_PRINCIPALS` |
| non-loopback production | registry must be non-empty; every token >= 24 chars and not `replace-`-prefixed, mirroring the existing check at `config.ts:69-76` |
| empty registry on loopback | legal — see below |

An empty registry stays legal on loopback dev, preserving today's zero-config behaviour
for every route *except* approvals. This is the deliberate cost of decision 2: a
developer who wants to approve something locally sets one env var. Failing closed here
rather than inventing a local identity is what keeps the invariant absolute.

`AppConfig` gains `principals: PrincipalRegistry` and drops `authToken`.

## `principals.ts`

```ts
export class PrincipalRegistry {
  static parse(raw: string): PrincipalRegistry;
  get size(): number;
  resolve(bearerToken: string): Principal | null;
}
```

Construction stores a `Map<sha256hex, Principal>`. `resolve` hashes the candidate and
performs a map lookup, rather than looping `timingSafeEqual` over every token: there is
no secret-dependent comparison, and the work does not scale with how many principals
exist. Extracted as its own module so parsing and resolution are unit-testable without
Fastify and without `AgentService` — the same factoring as `command-policy.ts` and
`capabilities.ts`.

## Auth boundary: `app.ts`

`request.principal: Principal | null` via `decorateRequest` plus declaration merging.
`/api/health` and `/api/auth` stay exempt as they are today.

| Registry | Bearer | Result |
| --- | --- | --- |
| empty | any / none | allowed, `principal = null` (today's open dev behaviour) |
| non-empty | absent or unresolvable | 401 `Authentication required` |
| non-empty | resolves | allowed, `principal` set |

`/api/auth` keeps reporting `{ required }`, now derived from `registry.size > 0`.

## Approvals endpoint

```ts
const approvalDecisionBody = z
  .object({
    decision: z.enum(["approve", "deny"]),
    reason: z.string().trim().min(1).max(2000),
  })
  .strict();
```

`.strict()` is load-bearing. Zod's default behaviour strips unknown keys, so a client
still sending `actor` would be silently ignored — the vulnerability hidden rather than
removed. Strict mode returns 400 and tells the caller the field is gone.

The handler refuses before touching the service:

```ts
if (!request.principal) {
  return reply.code(401).send({
    error: "Resolving an approval requires an authenticated principal. Set APP_PRINCIPALS.",
  });
}
```

New `GET /api/me` returns `{ principal: { id } | null }` so the UI can show who it is
deciding as. It cannot be folded into `/api/auth`, which is exempt from the auth hook and
therefore has no principal to report.

## Service

`resolveApproval(id, decision, principal: Principal, reason)` sets
`resolvedBy = principal.id`. The "An approver name is required" guard at
`agent-service.ts:201-204` is deleted — unrepresentable once the argument is a resolved
`Principal`. The reason guard stays. The single-mutation transaction and the 409 paths
are untouched.

## Web

Delete the `approver` state (`App.tsx:241`) and its input (`App.tsx:994-997`); the token
box already collects the credential, so asking for a name again is asking the client to
assert identity. `api.resolveApproval` loses its `actor` parameter. Bootstrap calls
`/api/me`; the buttons read "Approve as `<id>`" / "Deny as `<id>`", and when the
principal is null they are disabled with an explanation pointing at `APP_PRINCIPALS`
rather than failing at the server.

## Migration

`APP_AUTH_TOKEN` is removed everywhere it appears: `.env.example:8`, `README.md:448`,
`README.md:511`, `docs/DEPLOYMENT.md:100`, `:114-115`, `:127`, `SECURITY.md:26`,
`deploy/volcengine/main.tf:37`, `deploy/volcengine/variables.tf:68-75` (the
`app_auth_token` variable and its validation become `app_principals`), and
`scripts/deploy-volcengine.sh:27-33`. `docker-compose.yml` needs no change: it passes the
environment through `env_file`, so dropping the key from `.env.example` is sufficient.
Terraform must be updated in the same change:
leaving it to inject `APP_AUTH_TOKEN` would make every cloud deploy fail the new startup
check.

The startup throw is the migration notice. It fires only when `APP_AUTH_TOKEN` is
actually set, so an environment that never had it — including the current local `.env`,
which holds only the three `ARK_*` keys — is unaffected.

## Docs

| File | Change |
| --- | --- |
| `README.md:443-449`, `:505-517` | `APP_PRINCIPALS` in the required values and the env table |
| `README.md:323` | "requires a named approver + reason" becomes an authenticated principal + reason |
| `docs/DEPLOYMENT.md:95-127` | principal-based curl example; HTTPS caveat retained |
| `docs/ARCHITECTURE.md:28` | "The token is not user identity or authorization" becomes: the credential *is* identity, and is still not authorization |
| `docs/THREAT_MODEL.md:118-119` | "Approver identity is a label" is replaced by what remains — static registry, no roles, no four-eyes, no run attribution |
| `docs/OPERATIONAL_GOVERNANCE.md:47-49` | gap 3 rewritten the same way; gap 1 (audit-store access control) is untouched and still true |
| `SECURITY.md:26` | unique per-approver tokens |

## Tests

Written first, per the repo's TDD practice.

- `principals.test.ts` — parses a valid registry; rejects malformed entries, duplicate
  ids, duplicate tokens; `resolve` returns null for an unknown token; ids are preserved
  verbatim.
- `config-policy.test.ts` — `APP_AUTH_TOKEN` set throws with the migration message;
  non-loopback production without principals throws; a short or `replace-`-prefixed
  token throws.
- `app.test.ts` — a principal token authenticates a protected route; an unknown token is
  401; approval with no configured registry is 401; **approval carrying
  `actor: "someone-else"` in the body is 400, and on a valid request `resolvedBy` equals
  the token's principal id regardless of any body content.** That last assertion is the
  regression test for this entire change.
- `approval.test.ts` — existing call sites updated to pass a `Principal`; the deleted
  blank-actor case at `:255` is replaced by the endpoint-level 401 test.
