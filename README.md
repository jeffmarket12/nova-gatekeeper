# NovaGatekeeper — Proof Gatekeeper agent for zkVerify Agent Games

An autonomous agent for the **Proof Gatekeeper** event (account `@anonim`).
The platform POSTs signed payment tasks; the agent checks every field against
the registered condition, answers APPROVE/REJECT with a reason code, and
attaches a locally generated Groth16 proof that the decision followed the
rules. The platform re-verifies the proof against its own key and scores the
decision independently.

Plain JavaScript (CommonJS, no framework, no TypeScript). The only
dependencies are `snarkjs` (proving) and `js-sha3` (keccak256 task-id mode).

## Layout

```
api/agent.js        Vercel serverless entry point (POST /api/agent)
local-server.js     Local HTTP server for development + tests
src/
  config.js         Environment config (secret, modes, paths)
  hmac.js           HMAC-SHA256 verify/sign (hex + base64, constant-time)
  field.js          BN128 field helpers, task_id mapping, deterministic salt
  decision.js       Deterministic decision logic (the 7 outcomes)
  seen-store.js     Seen proof_tx set + task_id response cache (JSON file)
  prover.js         snarkjs fullProve / verify wrapper
  handler.js        Shared request handler (preflight, tasks, fail-closed)
test/
  trap-matrix.js    All 7 cases + boundaries + unprovable-wrong-decision
  handler.js        End-to-end HTTP test against the local server
circuits/
  gatekeeper.wasm / gatekeeper_final.zkey   (provided by the platform)
data/               Seen-store file (local default; gitignored)
vercel.json         Bundles circuits/** into the function, maxDuration 60
```

## Decision logic (deterministic, fail closed, mirrors the circuit)

| # | Check | Outcome |
|---|-------|---------|
| 1 | `proof_vk != registered_vk` (hex, case-insensitive) | REJECT `VK_SUBSTITUTION` |
| 2 | `proof_tx` already seen | REJECT `PROOF_REUSED` (no proof attached) |
| 3 | `public_balance < minimum` | REJECT `THRESHOLD_MISMATCH` |
| 4 | `current_block >= expiry_block` (note: `>=`, expired AT expiry) | REJECT `EXPIRED_CONDITION` |
| 5 | `recipient != condition_recipient` | REJECT `RECIPIENT_MISMATCH` |
| 6 | `amount > max_transfer` | REJECT `AMOUNT_OVERFLOW` |
| – | all pass | APPROVE `VALID_CONDITION` |

- Malformed envelope/fields, missing `task_id`, or a clearly past deadline
  → REJECT `INVALID_TASK` (HTTP 200, signed, no proof).
- Proving failure on an APPROVE → downgraded to REJECT `INVALID_TASK`
  (never return an unproven APPROVE). Proving failure on a REJECT → the
  REJECT is returned with its reason code and no proof.
- A wrong decision is **unprovable**: the circuit asserts the decision
  matches the checks (verified: APPROVE on a trap and REJECT on a valid task
  both throw at `GatekeeperEvaluation` line 102).
- `proof_tx` is recorded in the seen-set only AFTER a successful evaluation,
  so a task never flags itself. A redelivered `task_id` returns the cached
  response byte-identically without re-evaluating.

## Run locally

```bash
npm install
AGENT_GAMES_HMAC_SECRET=<secret> npm start   # listens on :8787 (PORT to change)
```

Test the health endpoint:

```bash
curl http://localhost:8787/health   # {"ok":true}
```

## Deploy to Vercel

```bash
npm i -g vercel   # once
vercel --prod     # from this directory
```

Then, in the Vercel project settings → Environment Variables, set:

- `AGENT_GAMES_HMAC_SECRET` — from the Agent Games dashboard ("Rotate
  Secret" for the agent; shown once as plaintext). Redeploy after setting it.
- `TASK_ID_MODE` — optional (default `sha256`; see below).

Register the endpoint in the dashboard as the full handler path:

```
https://<your-project>.vercel.app/api/agent
```

`vercel.json` bundles `circuits/**` into the function and sets
`maxDuration: 60`. The seen-store defaults to `/tmp/gatekeeper-seen.json` on
Vercel (the only writable path); see *Limitations*.

## Environment variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | yes | — | Raw UTF-8 string. Missing → POSTs answer 500. |
| `TASK_ID_MODE` | no | `sha256` | `sha256` \| `keccak256` \| `numeric` \| `hex` |
| `SEEN_STORE_PATH` | no | `data/seen.json` (`/tmp/gatekeeper-seen.json` on Vercel) | Seen-set + cache file |
| `CIRCUITS_DIR` | no | `circuits/` | wasm + zkey location |
| `PORT` | no | `8787` | Local server only |

## The task_id open question

The circuit takes `taskId` as a field element, but the platform does not
document how the string `task_id` (e.g. `gk_24_9d1`) maps to one. The agent
supports four mappings via `TASK_ID_MODE`:

- `sha256` (default): SHA-256 of the UTF-8 task_id, mod p.
- `keccak256`: keccak-256 of the UTF-8 task_id, mod p.
- `numeric`: the task_id's digits only, as a decimal integer, mod p.
- `hex`: the task_id's hex characters only, as a hex integer, mod p.

The proof verifies against the circuit's own key under ANY mapping (the
circuit only constrains the decision against the other inputs), so a wrong
mapping does not break local verification — but the platform may check the
`taskId` public signal against its own expected value, in which case a wrong
mapping could cost the reliability bonus or the proof's acceptance. **Resolve
this in Practice Mode before the first scored round**: run a practice task
under each mode and see which one the platform accepts. Switching modes is a
one-line env change + redeploy.

Note the salt is deterministic per task (`HMAC(secret, "gatekeeper-salt:"+task_id)`
mod p), so identical inputs stay identical across redeliveries; the response
cache is what guarantees byte-identical redelivered bodies (Groth16 proofs
are randomised per run).

## Protocol details

- Every inbound POST is HMAC-verified over the **raw body** before JSON is
  parsed. Inbound signatures accept lowercase/uppercase hex, base64, and an
  optional `sha256=` prefix. Bad signature → 401 (unsigned).
- Every 200/400 response is signed (`x-agent-games-signature`, lowercase
  hex HMAC-SHA256 over the raw response body). 401/500 responses are unsigned.
- Preflight (`agent-games.preflight.v1`) → signed `{ok:true, protocolVersion:"v1"}`.
- Task responses (provable): `{decision, reason_code, proof, public_signals,
  proof_tx}`. `PROOF_REUSED`: `{decision:"REJECT",
  reason_code:"PROOF_REUSED", proof_tx}` with no proof fields.
- The circuit has 13 public signals: the 12 non-salt inputs plus a salt
  commitment as signal 0 (verified empirically: changing only the salt
  changes only signal 0).
- Deadline handling: only a *parseable* deadline more than 5s in the past
  invalidates a task (clock-skew grace). An *unparseable* `deadline_at` is
  ignored and the task is evaluated normally — the platform enforces the 60s
  window itself, and a format surprise must not sink every task.
- Kurier / on-chain submission is NOT in scope for v1: the platform
  re-verifies the returned proof itself.

## Tests

```bash
npm test                # both suites
npm run test:trap-matrix
npm run test:handler
```

Measured on this VM (Nov 2026): proving ~0.9s cold / ~0.3s warm; full
handler latency ~0.9s cold / ~0.4s warm per task; redelivery ~3ms. All far
inside the 60s response window.

## Limitations / next steps

- **Seen-store on Vercel is per-instance and ephemeral** (`/tmp`): a cold
  start or a second instance loses the seen-set and the response cache. A
  missed PROOF_REUSED would cost −6 on that task. The store is a small
  interface (`src/seen-store.js`) designed to be swapped for a KV backend
  (Vercel KV / Upstash) without touching the handler.
- **TASK_ID_MODE is unverified** (see above) — confirm in Practice Mode.
- No Kurier on-chain submission (out of scope for v1 by design).
