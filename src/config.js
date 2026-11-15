'use strict';
/**
 * Central configuration, read from environment variables.
 *
 *   AGENT_GAMES_HMAC_SECRET  (required) Shared secret for HMAC-SHA256
 *                            verification of inbound tasks and signing of
 *                            outbound responses. Raw UTF-8 string, no default.
 *   TASK_ID_MODE             How the string task_id maps to a circuit field
 *                            element: "sha256" (default), "keccak256",
 *                            "numeric" (digits only) or "hex" (hex chars only).
 *   SEEN_STORE_PATH          JSON file for the seen proof_tx set + the
 *                            task_id -> response cache. Default:
 *                            <project>/data/seen.json locally, or
 *                            /tmp/gatekeeper-seen.json on Vercel (the only
 *                            writable path in a serverless function).
 *   CIRCUITS_DIR             Directory holding gatekeeper.wasm and
 *                            gatekeeper_final.zkey. Default: <project>/circuits.
 *   PORT                     Local server port (default 8787).
 */

const path = require('path');

const TASK_ID_MODES = ['sha256', 'keccak256', 'numeric', 'hex'];

function defaultSeenStorePath() {
  // Vercel sets VERCEL=1; its filesystem is read-only except /tmp.
  if (process.env.VERCEL === '1') return '/tmp/gatekeeper-seen.json';
  return path.join(__dirname, '..', 'data', 'seen.json');
}

function getConfig(env = process.env) {
  const taskIdMode = (env.TASK_ID_MODE || 'sha256').toLowerCase();
  if (!TASK_ID_MODES.includes(taskIdMode)) {
    throw new Error(
      `Invalid TASK_ID_MODE "${taskIdMode}" (expected one of: ${TASK_ID_MODES.join(', ')})`,
    );
  }
  const port = parseInt(env.PORT || '8787', 10);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`Invalid PORT "${env.PORT}"`);
  }
  return {
    // Empty string when unset: the handler answers 500 per request rather
    // than crashing the process at startup.
    secret: env.AGENT_GAMES_HMAC_SECRET || '',
    taskIdMode,
    seenStorePath: env.SEEN_STORE_PATH || defaultSeenStorePath(),
    circuitsDir: env.CIRCUITS_DIR || path.join(__dirname, '..', 'circuits'),
    port,
  };
}

module.exports = { getConfig, TASK_ID_MODES };
