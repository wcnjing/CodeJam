# Every Run the session produced

Read straight out of the store at `$LOCAL_POC_DATA_ROOT/data/sentinel.json`.
Runs 1 and 2 are the DNS-label bug: the Agent could not resolve its broker, so
it had no route to the model and the failure surfaced as a transport error
against the Ark URL. Run 3 is the same code path after the fix — the request
reached Ark and came back refused on the account's spend cap. Runs 4-6 are the
governance loop, once that cap was lifted.

## Run 1 — `6a509d41-8156-47a4-9b00-f14aa60d8cdb`

- created: `2026-08-31T13:07:32.495Z`
- status: **failed**
- error: `docker Runtime exited with code 1: stream disconnected before completion: error sending request for url (https://ark.ap-southeast.bytepluses.com/api/v3/responses)`

## Run 2 — `7fcbb2f9-4e45-44cb-b698-c6fca0864cb7`

- created: `2026-08-31T13:09:14.247Z`
- status: **failed**
- error: `docker Runtime exited with code 1: stream disconnected before completion: error sending request for url (https://ark.ap-southeast.bytepluses.com/api/v3/responses)`

## Run 3 — `22399f77-5971-4073-aef1-e6b98d964de2`

- created: `2026-08-31T13:15:07.620Z`
- status: **failed**
- error: `docker Runtime exited with code 1: exceeded retry limit, last status: 429 Too Many Requests, request id: 02178818210821099a3f43520201fc0164769d66e52699fe9315d`

## Run 4 — `a3605a3e-ba4d-4b07-8aef-cbade9bfe9e0`

- created: `2026-08-31T14:39:03.553Z`
- status: **held**
- error: `Blocked by command policy (network-egress-denied): Command contacts non-allowlisted host(s): registry.npmjs.org.`

## Run 5 — `4157a185-f1d6-408b-bf67-c4d18b7da254`

- created: `2026-08-31T14:42:22.144Z`
- status: **completed**

## Run 6 — `ab0f1875-7caf-44e0-8ea5-2d91dd9006dc`

- created: `2026-08-31T14:44:01.159Z`
- status: **completed**

## The approval record

```json
[
  {
    "id": "e4a10e78-c7dd-449b-bd94-92bcbf953114",
    "agentId": "d8da4472-7657-4c04-a087-ea659fc6f4f3",
    "runId": "a3605a3e-ba4d-4b07-8aef-cbade9bfe9e0",
    "prompt": "Check the latest published version of the react package by running: curl https://registry.npmjs.org/react",
    "rule": "network-egress-denied",
    "command": "/usr/bin/bash -c 'curl https://registry.npmjs.org/react'",
    "detail": "Command contacts non-allowlisted host(s): registry.npmjs.org.",
    "hosts": [
      "registry.npmjs.org"
    ],
    "status": "approved",
    "requestedAt": "2026-08-31T14:39:08.433Z",
    "resolvedBy": "alice",
    "resolvedByAttribution": "credential",
    "decisionReason": "Package registry lookup is legitimate for this task; granting for this run only.",
    "resolvedAt": "2026-08-31T14:42:22.144Z",
    "continuationRunId": "4157a185-f1d6-408b-bf67-c4d18b7da254"
  }
]
```

`resolvedByAttribution: "credential"` is the point: the approver is who the
presented token identifies, not a name typed into the request. `command` is
what the model actually chose to run, not what the operator asked for.
