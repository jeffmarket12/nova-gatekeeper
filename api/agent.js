'use strict';
/**
 * Vercel serverless entry point for the Proof Gatekeeper agent.
 *
 * Deployed URL: https://<project>.vercel.app/api/agent
 * (register exactly this path as the agent endpoint — the platform POSTs to
 * the registered URL verbatim, and a root path would 404.)
 *
 * The raw request body is read from the stream with no body parser, because
 * the HMAC signature must be verified over the exact bytes the platform sent.
 *
 * Environment (set in the Vercel project settings):
 *   AGENT_GAMES_HMAC_SECRET  required (from dashboard "Rotate Secret")
 *   TASK_ID_MODE             optional, default "sha256"
 *   SEEN_STORE_PATH          optional; defaults to /tmp/gatekeeper-seen.json
 *                            on Vercel (the only writable path)
 *
 * The circuit files are bundled via vercel.json "includeFiles".
 * Module-level state (store + prover) is reused across warm invocations.
 */

const { getConfig } = require('../src/config');
const { createSeenStore } = require('../src/seen-store');
const { Prover } = require('../src/prover');
const { createHandler } = require('../src/handler');

const config = getConfig();
const store = createSeenStore({ filePath: config.seenStorePath });
store.load();
const prover = new Prover({ circuitsDir: config.circuitsDir, taskIdMode: config.taskIdMode });
const handle = createHandler({ config, store, prover });

module.exports = async (req, res) => {
  try {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const rawBody = Buffer.concat(chunks);
    const result = await handle({ method: req.method, headers: req.headers, rawBody });
    res.writeHead(result.status, result.headers);
    res.end(result.body);
  } catch (err) {
    console.error('[agent] unhandled error:', err);
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'internal_error' }));
  }
};
