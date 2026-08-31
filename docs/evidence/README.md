# One live run, recorded

Everything in this directory came out of a single session on **2026-08-31**, on
one machine, against a real container engine. It exists because the containment
claims in `README.md` and `docs/EGRESS_CONTAINMENT.md` had until now been argued
from unit tests and from `verify:egress`, neither of which had ever driven the
product end to end from the browser. Doing that found a bug that made the
default configuration unusable, which is the case for recording runs rather than
reasoning about them.

| | |
| --- | --- |
| Host | macOS 26.5.1, arm64 |
| Engine | Docker 29.5.2 via Colima 0.10.3 (`Virtualization.Framework`, virtiofs) |
| Revision | `1affb80`, plus the two fixes described below |
| Model endpoint | BytePlus ModelArk, `deepseek-v4-pro-ga-260813` |
| State root | `LOCAL_POC_DATA_ROOT=~/.volc-agent-sentinel-evidence` (created empty) |
| Approver | `APP_PRINCIPALS=alice:<throwaway local token>` — synthetic, never a real credential |

## What is proven here, and what is not

| Claim | Status | Where |
| --- | --- | --- |
| `npm run poc` loads `.env` and builds the broker image itself | **proven** | `poc-run.log` |
| An Agent is created from the browser, with a seeded workspace | **proven** | `poc-run.log`, workspace hash below |
| Each run gets an `--internal` network and a dual-homed broker | **proven** | `docker-topology.log` |
| The Agent has no route off that network | **proven** | `agent-container-probes.log` §1, §3 |
| The collector is reachable — the negative result is not vacuous | **proven** | `agent-container-probes.log` §2, `collector-positive-control.log` |
| Zero collector requests for the whole session | **proven** | `collector.log` |
| Networks and containers are torn down after every run | **proven** | `docker-topology.log` |
| The Agent and its workspace survive a server restart | **proven** | below |
| A live model turn completes through the broker | **proven** | `run-records.md` runs 4-6 |
| A held Run is approved by a credential-derived principal and resumes | **proven** | `run-records.md`, approval record |
| The Agent stays usable after containment | **proven** | run 6 wrote `hello.txt` |

One thing an approval does **not** do is widen the network allowlist — see
"What approval actually grants" below. That is the loop behaving as designed,
and it is not what `README.md` used to say.

## The bug this run found

The first turn failed with `stream disconnected before completion: error sending
request for url (https://ark.ap-southeast.bytepluses.com/api/v3/responses)`,
which reads exactly like a model outage. It was not.

The broker's container name is also a **DNS label** — the Agent reaches it as
the host in `HTTPS_PROXY`, resolved by the network's embedded DNS.
`sentinel-` + instance id + agent UUID + `-broker` is **73 characters**, and a
DNS label may be **63**. The Agent resolved nothing, had no route to the model,
and failed against the Ark URL.

Every check was green while this was true:

- the unit tests used short ids (`agent-1`, `test-instance`);
- `verify:egress` generated its own short names;
- the readiness probe dialled `127.0.0.1` **inside** the broker, so it passed
  while the name the Agent actually uses resolved to nothing.

Two changes, both in this branch:

1. `containerName` is bounded to a valid DNS label, truncating with a
   deterministic digest so names stay unique and stale-topology cleanup still
   finds what to remove.
2. `buildBrokerProbeArgs` dials the broker **by name** over the embedded DNS
   rather than by loopback, so the readiness gate exercises the path the Agent
   will take. `verify:egress` now also pads its broker name to the full 63
   octets, so the live check runs at the boundary the product runs at.

After the fix the same turn reached Ark and came back **HTTP 429** — a quota
refusal from the endpoint, which is a different failure and the one below.

## The spend cap, and what lifting it showed

Runs 4-6 only exist because the account's model was paused mid-session:

```
429 TooManyRequests — SetLimitExceeded: Your account has reached the set
inference limit for the [deepseek-v4-pro-ga] model, and the model service has
been paused.
```

That is an account setting on the ModelArk console ("Safe Experience Mode"), not
a rate limit that clears on its own. It is worth recording because preflight had
**passed** while it was true: `npm run doctor` probed `GET /models`, which
answers 200 for a paused account, so it reported "credentials accepted" and
every Run then failed minutes later, after a full image build. `doctor` now
infers once for a few tokens and names the console fix; `--no-inference` skips
that call.

## What approval actually grants

Run 4 held on `network-egress-denied` for `registry.npmjs.org`. `alice` approved
it with a reason, and run 5 — the continuation — **completed**. But the Agent's
own summary of run 5 is the interesting part:

> `curl` isn't installed (`command not found`) … `npm view react version`
> reached the registry but returned `403 Forbidden` … Direct Node HTTPS/fetch
> attempts failed with `EAI_AGAIN` (DNS resolution).

The approval released the *policy* hold. It did not widen the *network*
allowlist, which the broker derives from `ARK_BASE_URL` alone: `EAI_AGAIN` is the
internal network having no resolver for an outside name, and the `403` is the
broker refusing a CONNECT to a destination that is not the model endpoint.

This is the two controls doing different jobs, and it is the stronger property —
no decision made inside the application can talk the network layer into a route.
It also means the demo script's "approve → the continuation reaches the
registry" was only ever true with `CONTAINER_EGRESS_ISOLATION=false`. `README.md`
now says so.

## The files

**`poc-run.log`** — `npm run poc` from a cold state root. The four `[local-poc]`
lines at the top are the launcher loading `.env` and building
`volc-egress-broker:local` without being asked, which is the whole of the
one-command claim.
`poc-run-attempt1-dns-bug.log` is the same command before the fix, kept because
it is the failure mode.

**`docker-topology.log`** — `docker ps` and `docker network ls` polled every
second, transitions only. Each run shows the same shape: the Agent on
`…-net` alone, the broker on `…-net` **and** `bridge`, the network flagged
`internal=true`, then both gone. The 73-character names appear before the fix
and the 63-character ones after it. The `dbg-`, `proxyprobe-`, `dnslen-` and
`probename-` entries are this investigation's own scratch containers.

**`agent-container-probes.log`** — the containment measurement, run with the
names the product generates. From inside the isolated Agent Runtime every
destination is `UNREACHABLE`, including the collector on the host and the cloud
metadata address; from an ordinary bridge container, using the *same image* and
the *same addresses*, all three `CONNECTED`. `/proc/net/route` shows one on-link
route and gateway `00000000`.

**`collector.log`** — `scripts/mock-collector.mjs` on 9099 for the whole
session: **0 requests**. `collector-positive-control.log` is the same listener
recording three hits from a plain bridge container, which is what makes the zero
mean something.

**`broker.log`** — the per-run broker's own output. Note what it does *not*
contain: the broker logs denials and readiness only, so an allowed CONNECT
leaves no line. An empty log is not evidence that nothing was tunnelled.

**`verify-egress.log`** — `npm run verify:egress`, 15/15 against Docker 29.5.2,
re-run after the fix with the broker name padded to 63 octets.

**`run-records.md`** — all six Run rows and the approval record, read out of
the store. `resolvedByAttribution: "credential"` is the row that matters for the
approver claim, and `command` is what the model actually chose to run.

**`poc-run-live.log`**, **`docker-topology-live.log`**, **`collector.log`** —
the second session, the one that produced runs 4-6. `collector-session1.log` and
`broker-session1.log` are the first session's equivalents.

**`replay-server.log`** — a replay-mode server used while the model was paused.
Both README screenshots were re-taken against the live container-mode instance
once it was not, so nothing shipped in `docs/assets/` comes from replay.

## Recovery, verified by hand

The server was stopped and restarted between the failing turn and the fixed one.
The Agent, its session and its workspace came back:

```
$ shasum -a 256 ~/.volc-agent-sentinel-evidence/workspaces/d8da4472-…/.secrets/customer-db-url.txt
886d76b924c1c48e1c15663a82cc6a62ac7ffebaae18d62a93467f369069f5ad   # before the runs
886d76b924c1c48e1c15663a82cc6a62ac7ffebaae18d62a93467f369069f5ad   # after them
```

The seeded canary is byte-identical after every run, including the held one.
Run 6, an ordinary task sent after containment, completed and wrote `hello.txt`
into the same workspace — the Agent stays usable. `docker ps -a` and
`docker network ls` were empty at the end of the session.

## Secret scan

`gitleaks git --config .gitleaks.toml --log-opts=--all` over the full history:
**143 commits scanned, no leaks found**. `.env.bak-before-principals` was a
local, untracked file — `git log --all --diff-filter=A` finds no `.env` variant
ever committed except `.env.example` — and `.gitignore` now excludes `.env*`
with `!.env.example`, so no editor or backup variant can be added by accident.
CI runs the same scan on every push with `fetch-depth: 0`.
