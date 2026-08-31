# Egress containment

Status: **wired and verified against a real engine.** `npm run verify:egress`
stands the topology up and checks it end to end; the latest run passed 15/15 on
Docker 29.5.2 via Colima, and a separate hand-driven session measured the same
containment from inside the real Agent Runtime — see
[docs/evidence/](evidence/). Read "What is still not proven" before citing this
anywhere.

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

**DNS is part of the containment.** The per-run network is created with
`--internal`, and Docker's embedded resolver does not forward external queries
on an internal network — verified: `getent` fails with `EAI_AGAIN` inside the
isolated container even though the embedded resolver is listed. The broker
closes that gap without widening the edge: it runs a tiny dependency-free DNS
forwarder (UDP and TCP, on `EGRESS_DNS_PORT`, default 53) that relays the
Agent's queries to its own resolvers, and the Agent's `--dns` points at the
broker's address on the isolated network — the only resolver the Agent can
reach. Resolution through the broker opens no hole: DNS answers alone cannot
carry data out, and every connection is still gated by the CONNECT allowlist or
has no route. Binding port 53 is why the broker container keeps exactly one
capability (`NET_BIND_SERVICE`) alongside `--cap-drop ALL`.

`CONTAINER_DNS` (comma-separated, **default empty**) passes `--dns` to the
broker container — the resolvers the forwarder relays to — and to the Agent
container in bridge mode (isolation off). It is for environments where the
inherited resolver is unreachable from containers (WSL NAT gateway, VPN-only
DNS): it is what keeps the *broker's* lookups working on the isolated network,
and it lets bridge-mode runs pick a resolver explicitly. On the isolated
network the Agent's own `--dns` is always the broker, never `CONTAINER_DNS`:
external resolvers are unreachable there by design.

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
5. Read the broker's address on the isolated network (`<engine> inspect`), so
   the Agent can be pointed at its only resolver with `--dns`. Without it the
   Agent could not resolve anything; a failure here refuses the run.
6. **Wait for the broker to accept connections**, then start the Agent. An Agent
   started against a broker that has not bound yet fails in a way that looks
   like a model outage — the failure most likely to be misread as flakiness
   rather than as containment being broken. If it never binds, the run is
   refused rather than started with no route out.

   The probe runs *inside* the broker, through `<engine> exec`, because nothing
   about this topology is reachable from the host: a container name resolves
   only through the network's embedded DNS, which only containers on that
   network may query, and the broker publishes no host port — publishing one
   would give anything on the host a second way into the edge we are keeping
   singular. A host-side `connect()` to the name or to the container IP fails on
   every platform we support. `verify:egress` asserts both halves: that the
   probe answers through the engine, and that the host *cannot* reach the
   broker. The second is the one that catches a probe written the wrong way,
   since a unit test pointed at `127.0.0.1` passes either way.

   The probe dials the broker **by name**, and that is not cosmetic. It used to
   dial `127.0.0.1` inside the broker, which answers yes while the name the
   Agent is pointed at resolves to nothing — and that is exactly what happened.
   A container name is also a DNS label, a DNS label is 63 octets, and
   `sentinel-` + instance id + agent UUID + `-broker` is 73. The first live
   end-to-end run had no route to the model and failed against the Ark URL as
   though the endpoint were down. `containerName` is now bounded to a valid
   label (truncated with a deterministic digest, so cleanup still finds stale
   topology), the probe resolves the same name the Agent uses, and
   `verify:egress` pads its own broker name to the full 63 octets so the live
   check runs at the boundary.

Teardown runs in a `finally`, including on every throwing path, so a failed run
does not leak a network the next setup would have to clear blind.

Any failure during setup tears down what was already created and throws. A
half-built topology would leave the Agent on an internal network with no broker,
which hangs rather than errors.

## What is still not proven

**An approval does not widen the broker's allowlist.** The broker allowlists the
model endpoint and nothing else, and a human approving a held egress releases the
*policy* hold only. In the recorded run the approved continuation ran the command
and still could not reach `registry.npmjs.org` — `EAI_AGAIN` direct, `403`
through the proxy. That is the intended split (no in-app decision can create a
route) but it is not what a reader expects from the word "approve", so it is
stated here and in `README.md` rather than left to be discovered.

**One engine, one platform.** Verified on Docker 29.5.2 on macOS. Podman is
wired (`--userns keep-id` is already handled for the Agent container) but has
not been exercised. Rootless Podman in particular treats `--internal` and
inter-container DNS differently enough to deserve its own run before it is
claimed.

**The verification uses a stand-in endpoint.** `verify:egress` allowlists
`example.com`, not a real Ark endpoint, because the check has to run without a
model key. The allow/deny boundary is what it proves; that a real Codex run
completes through the broker is a separate claim, and one this check does not
make — it is made instead by the recorded session in [docs/evidence/](evidence/),
where three live turns reached the model through the broker and nothing else.

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
| `CONTAINER_DNS` | *(empty)* | Comma-separated `--dns` resolvers for the broker (the resolvers its DNS forwarder relays to) and for the Agent in bridge mode. On the isolated network the Agent's `--dns` is always the broker. |

The broker allowlists exactly one endpoint, derived from `ARK_BASE_URL` via
`parseEgressEndpoint()`. One endpoint is the whole design: an allowlist with a
second entry is a policy, and a policy is the thing this control exists to stop
depending on.
