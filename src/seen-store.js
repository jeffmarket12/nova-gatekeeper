'use strict';
/**
 * Persistent store for:
 *   - the seen proof_tx set (PROOF_REUSED detection), and
 *   - the task_id -> response cache (idempotent redelivery).
 *
 * STORE INTERFACE (both backends implement it):
 *   load()                                kick off the initial load
 *   ready() -> Promise                    resolves when the initial load is done
 *   hasProofTx(canonicalTx) -> boolean    SYNC, in-memory only (call ready()
 *                                         first so a cold start has loaded)
 *   addProofTx(canonicalTx) -> Promise    memory + backend write (awaited)
 *   getResponse(taskId) -> Promise        memory, else backend on miss
 *   setResponse(taskId, {status, body}) -> Promise (awaited)
 *
 * hasProofTx stays synchronous on purpose: decide() takes a synchronous
 * reuse callback. The handler awaits ready() before deciding, so the
 * in-memory set is populated by then.
 *
 * Backends:
 *   - KvSeenStore (Upstash Redis via its REST API, plain fetch, no extra
 *     dependency): used when KV_REST_API_URL + KV_REST_API_TOKEN are set
 *     (Vercel project env vars, added when the Upstash integration is
 *     connected). Survives serverless cold starts and is shared across
 *     instances — the seen-set and response cache are authoritative.
 *   - JsonFileSeenStore: used otherwise (local dev + tests). On Vercel the
 *     file lives in /tmp, which is per-instance and ephemeral.
 *
 * Both backends never throw from persistence: a backend failure is logged
 * and the in-memory state keeps serving the current process.
 */

const fs = require('fs');
const path = require('path');

const SEEN_KEY = 'gk:seen';
const RESP_PREFIX = 'gk:resp:';

class JsonFileSeenStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.seen = new Set();
    this.responses = new Map();
  }

  load() {
    try {
      const raw = fs.readFileSync(this.filePath, 'utf8');
      const data = JSON.parse(raw);
      if (Array.isArray(data.seen)) {
        for (const tx of data.seen) {
          if (typeof tx === 'string') this.seen.add(tx);
        }
      }
      if (data.responses && typeof data.responses === 'object') {
        for (const [taskId, entry] of Object.entries(data.responses)) {
          if (entry && typeof entry.body === 'string') {
            this.responses.set(taskId, { status: entry.status || 200, body: entry.body });
          }
        }
      }
      console.log(
        `[seen-store] file: loaded ${this.seen.size} seen proof_tx, ` +
          `${this.responses.size} cached responses from ${this.filePath}`,
      );
    } catch (err) {
      if (err.code !== 'ENOENT') {
        console.error(`[seen-store] file: load failed (${err.message}); starting empty`);
      }
    }
  }

  async ready() {
    // File load is synchronous; nothing to wait for.
  }

  save() {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const data = {
        seen: [...this.seen],
        responses: Object.fromEntries(this.responses),
      };
      const tmpPath = `${this.filePath}.tmp`;
      fs.writeFileSync(tmpPath, JSON.stringify(data));
      fs.renameSync(tmpPath, this.filePath);
    } catch (err) {
      // Never crash request handling on a persistence failure.
      console.error(`[seen-store] file: save failed (${err.message}); in-memory state kept`);
    }
  }

  hasProofTx(canonicalTx) {
    return this.seen.has(canonicalTx);
  }

  async addProofTx(canonicalTx) {
    this.seen.add(canonicalTx);
    this.save();
  }

  async getResponse(taskId) {
    return this.responses.get(taskId);
  }

  async setResponse(taskId, entry) {
    this.responses.set(taskId, entry);
    this.save();
  }
}

class KvSeenStore {
  constructor(restUrl, restToken) {
    this.restUrl = restUrl.replace(/\/$/, '');
    this.restToken = restToken;
    this.seen = new Set();
    this.responses = new Map();
    this._readyPromise = null;
  }

  /** One Upstash REST command. Returns the `result` field, or throws. */
  async _cmd(command) {
    const res = await fetch(this.restUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.restToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(command),
    });
    if (!res.ok) {
      throw new Error(`KV ${command[0]} -> HTTP ${res.status}`);
    }
    const data = await res.json();
    if (data.error) {
      throw new Error(`KV ${command[0]} -> ${data.error}`);
    }
    return data.result;
  }

  load() {
    // Kick off the seen-set fetch; ready() awaits it. Responses are
    // fetched on demand (getResponse), not bulk-loaded.
    this._readyPromise = (async () => {
      try {
        const members = await this._cmd(['SMEMBERS', SEEN_KEY]);
        if (Array.isArray(members)) {
          for (const tx of members) {
            if (typeof tx === 'string') this.seen.add(tx);
          }
        }
        console.log(`[seen-store] kv: loaded ${this.seen.size} seen proof_tx`);
      } catch (err) {
        console.error(
          `[seen-store] kv: initial load failed (${err.message}); ` +
            'continuing with an empty in-memory set',
        );
      }
    })();
  }

  async ready() {
    if (this._readyPromise) await this._readyPromise;
  }

  hasProofTx(canonicalTx) {
    return this.seen.has(canonicalTx);
  }

  async addProofTx(canonicalTx) {
    this.seen.add(canonicalTx);
    try {
      await this._cmd(['SADD', SEEN_KEY, canonicalTx]);
    } catch (err) {
      console.error(`[seen-store] kv: SADD failed (${err.message}); in-memory state kept`);
    }
  }

  async getResponse(taskId) {
    const cached = this.responses.get(taskId);
    if (cached) return cached;
    try {
      const raw = await this._cmd(['GET', `${RESP_PREFIX}${taskId}`]);
      if (typeof raw === 'string' && raw.length > 0) {
        const entry = JSON.parse(raw);
        if (entry && typeof entry.body === 'string') {
          const normalized = { status: entry.status || 200, body: entry.body };
          this.responses.set(taskId, normalized);
          return normalized;
        }
      }
    } catch (err) {
      console.error(`[seen-store] kv: GET response failed (${err.message})`);
    }
    return undefined;
  }

  async setResponse(taskId, entry) {
    this.responses.set(taskId, entry);
    try {
      await this._cmd(['SET', `${RESP_PREFIX}${taskId}`, JSON.stringify(entry)]);
    } catch (err) {
      console.error(`[seen-store] kv: SET response failed (${err.message}); in-memory state kept`);
    }
  }
}

/** Pick the backend: KV when its env vars are present, else the JSON file. */
function createSeenStore({ filePath, env = process.env } = {}) {
  const url = env.KV_REST_API_URL || env.UPSTASH_REDIS_REST_URL;
  const token = env.KV_REST_API_TOKEN || env.UPSTASH_REDIS_REST_TOKEN;
  if (url && token) {
    console.log('[seen-store] using Upstash KV backend');
    return new KvSeenStore(url, token);
  }
  console.log('[seen-store] using JSON file backend');
  return new JsonFileSeenStore(filePath);
}

module.exports = { JsonFileSeenStore, KvSeenStore, createSeenStore };
