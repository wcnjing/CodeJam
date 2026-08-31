# Egress containment

Status: **mechanism built and tested, topology not yet wired.** Read the
"What is not done" section before citing this anywhere.

## Why this exists

`README.md` states the limitation plainly: our command network policy is *a
reactive command-text guard, not a network allowlist*, and the one residual it
names is a fully base64-encoded command the guard does not recognise.

That residual is not a bug in the guard. It is a property of guarding a network
the Agent can still reach: any encoding the policy has not modelled reaches the
internet, because the route is there to be reached. A text guard can be improved
indefinitely and never close it.

The structural answer is to remove the route. Put the Agent on a network with no
outbound path, and give it exactly one edge — a broker that will only ever
connect to the configured model endpoint. Then there is no second destination to
encode toward, and the residual has nowhere to land.

The command policy still matters and still runs. It is what produces the audit
record and the human hold, which a network control cannot do. What changes is
that it stops being the *only* thing between the Agent and the network.

## What is done

### `apps/server/src/egress-broker.ts`

An HTTP `CONNECT` proxy that fails closed on every path:

| Condition | Response |
| --- | --- |
| Not a `CONNECT` request | `400`, socket closed |
| Destination is not the allowlisted `(host, port)` | `403`, never resolved |
| DNS fails, or returns no addresses | `502` |
| Any resolved address is private/loopback/link-local/CGNAT | `403` |
| Allowlisted, all addresses public | `200`, bytes tunnelled |

Two decisions worth naming:

**The allowlist is checked before DNS.** An unknown hostname is never resolved,
so the broker cannot be used as a DNS oracle to probe internal names from its
own network position.

**Every resolved address is re-checked, not just the one we connect to.** An
allowlisted *hostname* is not a guarantee about the *address* it resolves to. An
attacker controlling DNS for a name we allow can point it at `127.0.0.1` or at
`169.254.169.254` and borrow the broker's network position — the classic DNS
rebinding gap that a hostname-string check leaves wide open. If any answer in
the set is private, the whole request is refused.

Covered by 16 tests in `egress-broker.test.ts`, including a real byte tunnel over
TCP. The tunnel test injects the socket dial rather than relaxing the address
check, so the rebinding guard stays armed while the tunnel is exercised.

### Container hardening — `container-codex-runner.ts`

`CONTAINER_READ_ONLY_ROOT` (**default on**) adds `--read-only` plus a
`nodev,nosuid,noexec` tmpfs at `/tmp`. Bind mounts are not part of the container
root filesystem, so the workspace and `CODEX_HOME` stay writable and the Agent
works normally; it simply cannot write elsewhere in its own image, and cannot
stage an executable in `/tmp`. Asserted at the argv level, both directions.

`CONTAINER_EGRESS_ISOLATION` (**default off**, see below) switches `--network`
from `bridge` to a per-run network and sets `HTTPS_PROXY` / `HTTP_PROXY` at the
broker with an empty `NO_PROXY`. The empty `NO_PROXY` is deliberate: a default
bypass list would let the Agent reach anything it could name as local without
passing the broker.

## What is not done

**The sidecar is not orchestrated, and this is why the flag defaults to off.**
Turning `CONTAINER_EGRESS_ISOLATION=true` today produces correct argv for a
topology nothing yet creates: no code creates the per-run `--internal` network,
starts a dual-homed broker container on it, waits for the broker to be ready, or
tears either down after the run. An Agent started that way would sit on a network
with no route to anything, including the broker, and every model call would fail.

Enabling it needs, in order:

1. A broker entrypoint (`egress-broker-cli.ts`) and a small image for it.
2. Network create/teardown around each run, attached to the run's lifecycle so a
   crashed run does not leak networks.
3. A readiness check before the Agent starts, so a broken sidecar aborts the run
   rather than letting it time out.
4. Verification against a real engine.

**Nothing here has been exercised against Docker or Podman.** No container engine
was available in the environment where this was written. The broker's own logic
is tested over real TCP on loopback; the container argv is asserted as strings.
The composed topology is unverified, and it should not be described as working
until someone has watched an Agent reach the model through the broker and watched
a non-allowlisted destination fail from inside the container.

**Until then the README limitation stands as written.** The base64 residual is
not retired. The mechanism that retires it exists and is tested; the wiring that
would put it in the path does not.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `CONTAINER_READ_ONLY_ROOT` | `true` | `--read-only` root plus a noexec `/tmp` tmpfs. |
| `CONTAINER_EGRESS_ISOLATION` | `false` | Per-run isolated network and broker proxy variables. Needs a broker; see above. |
| `CONTAINER_EGRESS_BROKER_HOST` | `launchpad-egress-broker` | Hostname the Agent's proxy variables point at. |

The broker allowlists exactly one endpoint, derived from `ARK_BASE_URL` via
`parseEgressEndpoint()`. One endpoint is the whole design: an allowlist with a
second entry is a policy, and a policy is the thing this control exists to stop
depending on.
