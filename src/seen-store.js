'use strict';
/**
 * Persistent store for:
 *   - the seen proof_tx set (PROOF_REUSED detection), and
 *   - the task_id -> response cache (idempotent redelivery).
 *
 * STORE INTERFACE (a KV backend can replace JsonFileSeenStore later by
 * implementing the same synchronous methods):
 *   load()                                populate memory from the backend
 *   hasProofTx(canonicalTx) -> boolean
 *   addProofTx(canonicalTx)               persist after adding
 *   getResponse(taskId) -> {status, body} | undefined
 *   setResponse(taskId, {status, body})   persist after setting
 *
 * The JSON-file implementation writes atomically (temp file + rename) and
 * never throws from save(): a persistence failure is logged and the
 * in-memory state keeps serving the current process. On Vercel the file
 * lives in /tmp, which is per-instance and ephemeral — the in-memory state
 * is authoritative there, and a KV backend is the planned upgrade.
 */

const fs = require('fs');
const path = require('path');

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
        `[seen-store] loaded ${this.seen.size} seen proof_tx, ` +
          `${this.responses.size} cached responses from ${this.filePath}`,
      );
    } catch (err) {
      if (err.code !== 'ENOENT') {
        console.error(`[seen-store] load failed (${err.message}); starting empty`);
      }
    }
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
      console.error(`[seen-store] save failed (${err.message}); in-memory state kept`);
    }
  }

  hasProofTx(canonicalTx) {
    return this.seen.has(canonicalTx);
  }

  addProofTx(canonicalTx) {
    this.seen.add(canonicalTx);
    this.save();
  }

  getResponse(taskId) {
    return this.responses.get(taskId);
  }

  setResponse(taskId, entry) {
    this.responses.set(taskId, entry);
    this.save();
  }
}

module.exports = { JsonFileSeenStore };
