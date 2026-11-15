'use strict';
/**
 * Handler test: spins up the real local server as a child process and talks
 * to it over HTTP with correctly/incorrectly HMAC-signed requests.
 *
 * Covers: health, signed preflight (+ base64 signature variant), 401 on a
 * bad signature, a valid signed task (proof verified locally), byte-identical
 * redelivery of the same task_id, and PROOF_REUSED on a second task sharing
 * the first task's proof_tx. Reports per-task handler latency.
 *
 * Run: node test/handler.js   (or: npm run test:handler)
 * Exit code 0 = all assertions passed.
 */

const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { signHex, verifySignature } = require('../src/hmac');
const { Prover } = require('../src/prover');

const SECRET = 'handler-test-secret';
const PORT = 18787;
const BASE = `http://127.0.0.1:${PORT}`;

const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const ADDR = '0x1111111111111111111111111111111111111111';

let passed = 0;
let failed = 0;

function check(name, condition, extra = '') {
  if (condition) {
    passed += 1;
    console.log(`  PASS  ${name}`);
  } else {
    failed += 1;
    console.log(`  FAIL  ${name}${extra ? ` — ${extra}` : ''}`);
  }
}

function request({ method, path: urlPath, body, headers = {} }) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      `${BASE}${urlPath}`,
      { method, headers: { 'content-type': 'application/json', ...headers } },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        }));
      },
    );
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function signedPost(envelope, secret = SECRET) {
  const body = JSON.stringify(envelope);
  return { body, headers: { 'x-agent-games-signature': signHex(secret, Buffer.from(body, 'utf8')) } };
}

function taskEnvelope(taskId, proofTx, overrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId,
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK,
      proof_vk: VK,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: '19842201',
      current_block: '19832000',
      recipient: ADDR,
      condition_recipient: ADDR,
      amount: '500',
      max_transfer: '1000',
      proof_tx: proofTx,
      ...overrides,
    },
  };
}

async function waitForHealth(server, timeoutMs = 15000) {
  const started = Date.now();
  for (;;) {
    try {
      const res = await request({ method: 'GET', path: '/health' });
      if (res.status === 200) return;
    } catch {
      // Not up yet.
    }
    if (Date.now() - started > timeoutMs) {
      throw new Error('server did not come up in time');
    }
    if (server.exitCode !== null) {
      throw new Error(`server exited early with code ${server.exitCode}`);
    }
    await new Promise((r) => setTimeout(r, 200));
  }
}

async function main() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gk-handler-'));
  const seenPath = path.join(tmpDir, 'seen.json');
  const prover = new Prover({
    circuitsDir: path.join(__dirname, '..', 'circuits'),
    taskIdMode: 'sha256',
  });

  const server = spawn(
    process.execPath,
    [path.join(__dirname, '..', 'local-server.js')],
    {
      env: {
        ...process.env,
        AGENT_GAMES_HMAC_SECRET: SECRET,
        PORT: String(PORT),
        SEEN_STORE_PATH: seenPath,
        TASK_ID_MODE: 'sha256',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  let serverLog = '';
  server.stdout.on('data', (d) => { serverLog += d; });
  server.stderr.on('data', (d) => { serverLog += d; });

  try {
    await waitForHealth(server);

    console.log('=== 1. GET /health ===');
    const health = await request({ method: 'GET', path: '/health' });
    check('status 200', health.status === 200, `got ${health.status}`);
    check('body {ok:true}', health.body === JSON.stringify({ ok: true }), health.body);

    console.log('\n=== 2. Signed preflight ===');
    const preflight = {
      type: 'agent-games.preflight.v1',
      agent_id: 'test-agent',
      issued_at: new Date().toISOString(),
      nonce: 'nonce-123',
    };
    const pf = signedPost(preflight);
    const pfRes = await request({ method: 'POST', path: '/agent', body: pf.body, headers: pf.headers });
    check('status 200', pfRes.status === 200, `got ${pfRes.status}: ${pfRes.body}`);
    const pfJson = JSON.parse(pfRes.body);
    check('body {ok:true, protocolVersion:"v1"}',
      pfJson.ok === true && pfJson.protocolVersion === 'v1', pfRes.body);
    check('response signature verifies',
      verifySignature(SECRET, Buffer.from(pfRes.body, 'utf8'), pfRes.headers['x-agent-games-signature']));

    console.log('\n=== 3. Preflight with base64 signature (accepted variant) ===');
    const b64Body = JSON.stringify(preflight);
    const b64Sig = Buffer.from(signHex(SECRET, Buffer.from(b64Body, 'utf8')), 'hex').toString('base64');
    const b64Res = await request({
      method: 'POST', path: '/agent', body: b64Body,
      headers: { 'x-agent-games-signature': b64Sig },
    });
    check('status 200 with base64 signature', b64Res.status === 200, `got ${b64Res.status}`);

    console.log('\n=== 4. Bad signature -> 401 ===');
    const bad = signedPost(taskEnvelope('gk_h_bad', '0xbad0000000000000000000000000000000000000000000000000000000000000'), 'wrong-secret');
    const badRes = await request({ method: 'POST', path: '/agent', body: bad.body, headers: bad.headers });
    check('status 401', badRes.status === 401, `got ${badRes.status}`);
    check('401 response is unsigned', !badRes.headers['x-agent-games-signature']);
    const unsigned = await request({
      method: 'POST', path: '/agent', body: JSON.stringify(taskEnvelope('gk_h_unsigned', '0xbad1000000000000000000000000000000000000000000000000000000000000')),
    });
    check('missing signature -> 401', unsigned.status === 401, `got ${unsigned.status}`);

    console.log('\n=== 5. Valid signed task (cold prove) ===');
    const proofTxA = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const t1 = taskEnvelope('gk_h_1', proofTxA);
    const t1Signed = signedPost(t1);
    const startCold = Date.now();
    const t1Res = await request({ method: 'POST', path: '/agent', body: t1Signed.body, headers: t1Signed.headers });
    const coldLatency = Date.now() - startCold;
    check('status 200', t1Res.status === 200, `got ${t1Res.status}: ${t1Res.body}`);
    const t1Json = JSON.parse(t1Res.body);
    check('decision APPROVE', t1Json.decision === 'APPROVE', t1Res.body);
    check('reason VALID_CONDITION', t1Json.reason_code === 'VALID_CONDITION', t1Res.body);
    check('proof present', !!t1Json.proof && typeof t1Json.proof === 'object');
    check('public_signals present (13)', Array.isArray(t1Json.public_signals) && t1Json.public_signals.length === 13);
    check('proof_tx echoed', t1Json.proof_tx === proofTxA);
    check('response signature verifies',
      verifySignature(SECRET, Buffer.from(t1Res.body, 'utf8'), t1Res.headers['x-agent-games-signature']));
    const proofOk = await prover.verify(t1Json.proof, t1Json.public_signals);
    check('returned proof verifies locally', proofOk === true);
    console.log(`  (handler latency, cold: ${coldLatency}ms)`);

    console.log('\n=== 6. Redelivery of the same task_id (cached, byte-identical) ===');
    const startRedeliver = Date.now();
    const t1Again = await request({ method: 'POST', path: '/agent', body: t1Signed.body, headers: t1Signed.headers });
    const redeliverLatency = Date.now() - startRedeliver;
    check('status 200', t1Again.status === 200);
    check('body byte-identical to first response', t1Again.body === t1Res.body);
    check('signature identical to first response',
      t1Again.headers['x-agent-games-signature'] === t1Res.headers['x-agent-games-signature']);
    console.log(`  (redelivery latency: ${redeliverLatency}ms — no re-proving)`);

    console.log('\n=== 7. Second valid task (warm prove) ===');
    const t2Signed = signedPost(taskEnvelope('gk_h_2',
      '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'));
    const startWarm = Date.now();
    const t2Res = await request({ method: 'POST', path: '/agent', body: t2Signed.body, headers: t2Signed.headers });
    const warmLatency = Date.now() - startWarm;
    const t2Json = JSON.parse(t2Res.body);
    check('status 200 + APPROVE', t2Res.status === 200 && t2Json.decision === 'APPROVE', t2Res.body);
    console.log(`  (handler latency, warm: ${warmLatency}ms)`);

    console.log('\n=== 8. Same proof_tx, different task_id -> PROOF_REUSED ===');
    const t3Signed = signedPost(taskEnvelope('gk_h_3', proofTxA));
    const t3Res = await request({ method: 'POST', path: '/agent', body: t3Signed.body, headers: t3Signed.headers });
    const t3Json = JSON.parse(t3Res.body);
    check('status 200', t3Res.status === 200, `got ${t3Res.status}`);
    check('decision REJECT', t3Json.decision === 'REJECT', t3Res.body);
    check('reason PROOF_REUSED', t3Json.reason_code === 'PROOF_REUSED', t3Res.body);
    check('no proof attached', !('proof' in t3Json) && !('public_signals' in t3Json));
    check('proof_tx echoed', t3Json.proof_tx === proofTxA);

    console.log('\n=== 9. Malformed task -> REJECT INVALID_TASK (200, signed) ===');
    const malformed = taskEnvelope('gk_h_4',
      '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc');
    delete malformed.input.amount; // missing required field
    const mSigned = signedPost(malformed);
    const mRes = await request({ method: 'POST', path: '/agent', body: mSigned.body, headers: mSigned.headers });
    const mJson = JSON.parse(mRes.body);
    check('status 200', mRes.status === 200, `got ${mRes.status}`);
    check('decision REJECT / INVALID_TASK',
      mJson.decision === 'REJECT' && mJson.reason_code === 'INVALID_TASK', mRes.body);
    check('response signed',
      verifySignature(SECRET, Buffer.from(mRes.body, 'utf8'), mRes.headers['x-agent-games-signature']));

    console.log(`\n=== RESULT: ${passed} passed, ${failed} failed ===`);
    console.log(`Latencies: cold ${coldLatency}ms, warm ${warmLatency}ms, redelivery ${redeliverLatency}ms`);
  } finally {
    server.kill('SIGTERM');
    // Give it a moment, then force.
    await new Promise((r) => setTimeout(r, 500));
    if (server.exitCode === null) server.kill('SIGKILL');
    if (failed > 0) {
      console.log('\n--- server log ---\n' + serverLog);
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('HANDLER TEST CRASHED:', err);
  process.exit(1);
});
