'use strict';
/**
 * Shared request handler for the Proof Gatekeeper agent.
 *
 * Used by both the Vercel serverless function (api/agent.js) and the local
 * test server (local-server.js). Transport-agnostic: it takes a plain
 * request object and returns a plain response object.
 *
 *   handle({ method, headers, rawBody: Buffer })
 *     -> { status, headers, body }   (body is a string)
 *
 * Protocol:
 *   - GET  -> {ok:true} health (signed when a secret is configured).
 *   - POST -> HMAC-SHA256 over the RAW body is verified BEFORE any JSON
 *             parsing. Missing secret -> 500, bad signature -> 401, both
 *             unsigned. Every 200/400 response body is signed with
 *             x-agent-games-signature (lowercase hex).
 *   - Preflight envelope -> signed {ok:true, protocolVersion:"v1"}.
 *   - Task envelope -> deterministic decision + Groth16 proof (see below).
 *   - Unknown envelope type -> signed 400.
 *
 * Task flow (fail closed at every step):
 *   1. Redelivered task_id? Return the cached response verbatim, WITHOUT
 *      re-evaluating (so a redelivery is never misread as proof reuse).
 *   2. Deadline clearly past? REJECT / INVALID_TASK (200, signed).
 *   3. Malformed fields? REJECT / INVALID_TASK (200, signed).
 *   4. Decide (see decision.js). Record proof_tx in the seen-set ONLY after
 *      a successful evaluation, so a task never flags itself.
 *   5. PROOF_REUSED -> respond with NO proof (there is none to attach).
 *      Other outcomes -> generate the Groth16 proof:
 *        - proving fails on an APPROVE -> downgrade to REJECT / INVALID_TASK
 *          (never return an unproven APPROVE);
 *        - proving fails on a REJECT -> return the REJECT with its
 *          reason_code and no proof.
 *   6. Cache the response under task_id and return it signed.
 */

const { decide } = require('./decision');
const { signHex, verifySignature } = require('./hmac');
const { canonicalProofTx } = require('./field');

const PREFLIGHT_TYPE = 'agent-games.preflight.v1';
const TASK_TYPE = 'agent-games.proof-gatekeeper.v1';

// A deadline is only "clearly in the past" once it is more than this far
// behind the local clock, to tolerate clock skew between us and the platform.
const DEADLINE_GRACE_MS = 5000;

function getHeader(headers, name) {
  if (!headers) return undefined;
  const direct = headers[name];
  if (direct !== undefined) return Array.isArray(direct) ? direct[0] : direct;
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) {
      const value = headers[key];
      return Array.isArray(value) ? value[0] : value;
    }
  }
  return undefined;
}

/**
 * Parse a deadline value (ISO string, epoch ms or epoch seconds, as a number
 * or digit string) into epoch ms, or null when it cannot be understood.
 * An unparseable deadline is IGNORED (the task is evaluated normally) rather
 * than invalidating the task: the platform enforces the 60s window itself,
 * and a format surprise must not sink every task.
 */
function parseDeadlineMs(value) {
  if (value === undefined || value === null) return null;
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value > 1e12 ? value : value * 1000;
  }
  if (typeof value === 'string') {
    const s = value.trim();
    if (/^[0-9]+$/.test(s)) {
      const n = Number(s);
      return n > 1e12 ? n : n * 1000;
    }
    const ms = Date.parse(s);
    return Number.isNaN(ms) ? null : ms;
  }
  return null;
}

function createHandler({ config, store, prover }) {
  const { secret } = config;

  function signedRaw(status, body) {
    return {
      status,
      headers: {
        'content-type': 'application/json',
        'x-agent-games-signature': signHex(secret, Buffer.from(body, 'utf8')),
      },
      body,
    };
  }

  function signed(status, obj) {
    return signedRaw(status, JSON.stringify(obj));
  }

  function unsigned(status, obj) {
    return {
      status,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(obj),
    };
  }

  /** Build the INVALID_TASK response, echoing proof_tx when available. */
  function invalidTaskResponse(envelope) {
    const response = { decision: 'REJECT', reason_code: 'INVALID_TASK' };
    const proofTx = envelope && envelope.input && envelope.input.proof_tx;
    if (typeof proofTx === 'string' && proofTx.trim() !== '') {
      response.proof_tx = proofTx;
    }
    return response;
  }

  /** Record a task's proof_tx as seen (best effort, never throws). */
  async function recordProofTx(envelope) {
    try {
      const proofTx = envelope && envelope.input && envelope.input.proof_tx;
      if (typeof proofTx === 'string' && proofTx.trim() !== '') {
        await store.addProofTx(canonicalProofTx(proofTx));
      }
    } catch (err) {
      console.error(`[gatekeeper] recordProofTx failed: ${err.message}`);
    }
  }

  /** Finish a task: cache the response under task_id and return it signed. */
  async function finish(taskId, responseObj) {
    const res = signed(200, responseObj);
    if (taskId) {
      await store.setResponse(taskId, { status: res.status, body: res.body });
    }
    return res;
  }

  async function handleTask(envelope) {
    const taskId =
      typeof envelope.task_id === 'string' && envelope.task_id.length > 0
        ? envelope.task_id
        : null;

    // A task without a task_id is a malformed envelope: no proving, no
    // caching, no proof_tx recording — just INVALID_TASK.
    if (!taskId) {
      console.log('[gatekeeper] missing task_id -> INVALID_TASK');
      return await finish(null, invalidTaskResponse(envelope));
    }

    // Wait for the store's initial load (a cold start fetching the seen-set
    // from KV) before any read: hasProofTx is sync against memory.
    await store.ready();

    // 1. Idempotent redelivery: same task_id -> same response, no re-eval.
    const cached = await store.getResponse(taskId);
    if (cached) {
      console.log(`[gatekeeper] ${taskId} redelivered -> cached response`);
      // Byte-identical body (HMAC is deterministic, so the signature
      // matches the original response too).
      return signedRaw(cached.status, cached.body);
    }

    // 2. Deadline: only a CLEARLY past, parseable deadline invalidates.
    if (envelope.deadline_at !== undefined && envelope.deadline_at !== null) {
      const deadlineMs = parseDeadlineMs(envelope.deadline_at);
      if (deadlineMs !== null && Date.now() > deadlineMs + DEADLINE_GRACE_MS) {
        console.log(`[gatekeeper] ${taskId || '?'} deadline passed -> INVALID_TASK`);
        // The fields were readable, so the proof was genuinely seen.
        await recordProofTx(envelope);
        return await finish(taskId, invalidTaskResponse(envelope));
      }
      if (deadlineMs === null) {
        console.log(`[gatekeeper] ${taskId || '?'} unparseable deadline_at, ignoring`);
      }
    }

    // 3. Decide. Malformed fields throw -> INVALID_TASK (no proof_tx
    // recorded: an unparseable task cannot be trusted).
    let outcome;
    try {
      outcome = decide(envelope.input, (proofTx) => {
        try {
          return store.hasProofTx(canonicalProofTx(proofTx));
        } catch {
          return false;
        }
      });
    } catch (err) {
      console.log(`[gatekeeper] ${taskId || '?'} malformed: ${err.message} -> INVALID_TASK`);
      return await finish(taskId, invalidTaskResponse(envelope));
    }

    // 4. Record proof_tx only AFTER a successful evaluation.
    await recordProofTx(envelope);

    const proofTx = envelope.input.proof_tx;

    // 5a. PROOF_REUSED carries no proof.
    if (!outcome.provable) {
      console.log(`[gatekeeper] ${taskId} -> REJECT PROOF_REUSED (no proof)`);
      return await finish(taskId, {
        decision: 'REJECT',
        reason_code: 'PROOF_REUSED',
        proof_tx: proofTx,
      });
    }

    // 5b. Provable outcome: generate the Groth16 proof.
    const started = Date.now();
    try {
      const circuitInput = prover.buildInput(taskId, outcome.fields, outcome.decision, secret);
      const { proof, publicSignals } = await prover.prove(circuitInput);
      console.log(
        `[gatekeeper] ${taskId} -> ${outcome.decision} ${outcome.reasonCode} ` +
          `(proved in ${Date.now() - started}ms)`,
      );
      return await finish(taskId, {
        decision: outcome.decision,
        reason_code: outcome.reasonCode,
        proof,
        public_signals: publicSignals,
        proof_tx: proofTx,
      });
    } catch (err) {
      console.log(
        `[gatekeeper] ${taskId} proving failed (${err.message}); failing closed`,
      );
      if (outcome.decision === 'APPROVE') {
        // Never return an unproven APPROVE.
        return await finish(taskId, {
          decision: 'REJECT',
          reason_code: 'INVALID_TASK',
          proof_tx: proofTx,
        });
      }
      return await finish(taskId, {
        decision: 'REJECT',
        reason_code: outcome.reasonCode,
        proof_tx: proofTx,
      });
    }
  }

  async function handle({ method, headers, rawBody }) {
    const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody || '');

    // Health check (any GET). Signed when a secret is configured.
    if (method === 'GET') {
      if (secret) return signed(200, { ok: true });
      return unsigned(200, { ok: true });
    }
    if (method !== 'POST') {
      return unsigned(405, { error: 'method_not_allowed' });
    }

    // Authenticate BEFORE parsing.
    if (!secret) {
      console.error('[gatekeeper] AGENT_GAMES_HMAC_SECRET is not set');
      return unsigned(500, { error: 'misconfigured' });
    }
    const signature = getHeader(headers, 'x-agent-games-signature');
    if (!verifySignature(secret, body, signature)) {
      return unsigned(401, { error: 'unauthorized' });
    }

    let envelope;
    try {
      envelope = JSON.parse(body.toString('utf8'));
    } catch {
      return signed(400, { error: 'invalid_json' });
    }
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
      return signed(400, { error: 'invalid_envelope' });
    }

    if (envelope.type === PREFLIGHT_TYPE) {
      return signed(200, { ok: true, protocolVersion: 'v1' });
    }
    if (envelope.type === TASK_TYPE) {
      try {
        return await handleTask(envelope);
      } catch (err) {
        // Last-resort fail closed: never leave a task unanswered.
        console.error(`[gatekeeper] unexpected task error: ${err.stack || err.message}`);
        return await finish(
          typeof envelope.task_id === 'string' ? envelope.task_id : null,
          invalidTaskResponse(envelope),
        );
      }
    }
    return signed(400, { error: 'unknown_type' });
  }

  return handle;
}

module.exports = { createHandler, PREFLIGHT_TYPE, TASK_TYPE };
