# Egress containment

Status: **wired and verified against a real engine.** `npm run verify:egress`
stands the topology up and checks it end to end; the run that accompanied this
document passed 11/11 on Docker 29.5.2. Read "What is still not proven" before
citing this anywhere.

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

`CONTAINER_EGRESS_ISOLATION` (**default on**) switches `--network` from `bridge`
to the per-run network and points `HTTPS_PROXY` / `HTTP_PROXY` at that run's own
broker, with an empty `NO_PROXY`. The empty `NO_PROXY` is deliberate: a default
bypass list would let the Agent reach anything it could name as local without
passing the broker. The broker is per-run rather than shared, so one compromised
Agent cannot reach or exhaust the broker another run depends on.

It defaults on because the container runtime is itself opt-in — anyone on this
path wants the hardened one. It needs the broker image (`npm run build:broker`),
and `isAvailable()` checks for it, so a missing image is reported up front
instead of failing the first run. There is no silent downgrade to an unisolated
runtime.

## Orchestration

`network-isolation.ts` owns the per-run lifecycle, and the order is the design:

1. Clear any stale network and broker. The names derive from the container name
   and so are deterministic, which means a crashed previous run would otherwise
   make "already exists" the normal startup path.
2. Create the `--internal` network. This is the control: the engine installs no
   NAT and no gateway, so nothing attached to it has a route out.
3. Start the broker on that network, itself contained — `--read-only`,
   `--cap-drop ALL`, `no-new-privileges`, unprivileged user. It is what an
   escaped Agent attacks next, so it gets the same treatment as the Agent.
4. Connect the broker to an outbound network as well. It is now dual-homed: the
   single object with a foot on both sides.
5. **Wait for the broker to accept connections**, then start the Agent. An Agent
   started against a broker that has not bound yet fails in a way that looks
   like a model outage — the failure most likely to be misread as flakiness
   rather than as containment being broken. If it never binds, the run is
   refused rather than started with no route out.

Teardown runs in a `finally`, including on every throwing path, so a failed run
does not leak a network the next setup would have to clear blind.

Any failure during setup tears down what was already created and throws. A
half-built topology would leave the Agent on an internal network with no broker,
which hangs rather than errors.

## What is still not proven

**One engine, one platform.** Verified on Docker 29.5.2 on macOS. Podman is
wired (`--userns keep-id` is already handled for the Agent container) but has
not been exercised. Rootless Podman in particular treats `--internal` and
inter-container DNS differently enough to deserve its own run before it is
claimed.

**The verification uses a stand-in endpoint.** `verify:egress` allowlists
`example.com`, not a real Ark endpoint, because the check has to run without a
model key. The allow/deny boundary is what it proves; that a real Codex run
completes through the broker is a separate claim, and one this check does not
make.

**The broker sees TLS as opaque bytes.** It gates the destination, not the
content. An allowlisted endpoint that is itself hostile, or an exfiltration
channel folded into legitimate traffic to that endpoint, is out of scope — the
command policy and the evidence trail are what address those.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `CONTAINER_READ_ONLY_ROOT` | `true` | `--read-only` root plus a noexec `/tmp` tmpfs. |
| `CONTAINER_EGRESS_ISOLATION` | `true` | Per-run isolated network and broker sidecar. |
| `CONTAINER_EGRESS_BROKER_IMAGE` | `volc-egress-broker:local` | Built by `npm run build:broker`. |
| `CONTAINER_EGRESS_BROKER_PORT` | `8080` | Port the broker listens on inside the network. |
| `CONTAINER_EGRESS_OUTBOUND_NETWORK` | `bridge` | The broker's second home. The Agent is never attached to it. |
| `CONTAINER_EGRESS_READY_TIMEOUT_MS` | `15000` | How long to wait for the broker before refusing the run. |

The broker allowlists exactly one endpoint, derived from `ARK_BASE_URL` via
`parseEgressEndpoint()`. One endpoint is the whole design: an allowlist with a
second entry is a policy, and a policy is the thing this control exists to stop
depending on.
