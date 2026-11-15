'use strict';
/**
 * Local HTTP server for the Proof Gatekeeper agent (development + tests).
 *
 * Usage:
 *   AGENT_GAMES_HMAC_SECRET=<secret> node local-server.js
 *
 * Listens on PORT (default 8787). Accepts POST on any path (the Vercel
 * function only exists at /api/agent; locally the path is irrelevant) and
 * answers GET with {ok:true}.
 */

const http = require('http');
const { getConfig } = require('./src/config');
const { createSeenStore } = require('./src/seen-store');
const { Prover } = require('./src/prover');
const { createHandler } = require('./src/handler');

const config = getConfig();
const store = createSeenStore({ filePath: config.seenStorePath });
store.load();
const prover = new Prover({ circuitsDir: config.circuitsDir, taskIdMode: config.taskIdMode });
const handle = createHandler({ config, store, prover });

const server = http.createServer(async (req, res) => {
  try {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const rawBody = Buffer.concat(chunks);
    const result = await handle({ method: req.method, headers: req.headers, rawBody });
    res.writeHead(result.status, result.headers);
    res.end(result.body);
  } catch (err) {
    console.error('[local-server] unhandled error:', err);
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'internal_error' }));
  }
});

server.listen(config.port, () => {
  console.log(`[gatekeeper] listening on http://localhost:${config.port}`);
  console.log(`[gatekeeper] taskIdMode=${config.taskIdMode}`);
  console.log(`[gatekeeper] seenStore=${config.seenStorePath}`);
  console.log(`[gatekeeper] secret ${config.secret ? 'SET' : 'MISSING (POSTs will 500)'}`);
});
