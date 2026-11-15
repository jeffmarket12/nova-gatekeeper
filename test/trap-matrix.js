'use strict';
/**
 * Trap-matrix test: every decision outcome + proof generation/verification.
 *
 * Uses the event page's sample numbers (minimum 1000, public_balance 1460,
 * expiry 19842201, current 19832000, amount 500, max_transfer 1000, matching
 * VKs/recipients) and runs all 7 cases (valid + 6 traps). For every provable
 * case the Groth16 proof is generated and verified locally against the
 * verification key exported from the .zkey. Also asserts a wrong decision is
 * unprovable (the circuit assert must throw).
 *
 * Run: node test/trap-matrix.js   (or: npm run test:trap-matrix)
 * Exit code 0 = all assertions passed.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { decide } = require('../src/decision');
const { Prover } = require('../src/prover');
const { JsonFileSeenStore } = require('../src/seen-store');
const { canonicalProofTx } = require('../src/field');

const SECRET = 'trap-matrix-test-secret';
const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const OTHER_VK = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
const ADDR = '0x1111111111111111111111111111111111111111';
const OTHER_ADDR = '0x2222222222222222222222222222222222222222';

let passed = 0;
let failed = 0;
const proveTimes = [];

function check(name, condition, extra = '') {
  if (condition) {
    passed += 1;
    console.log(`  PASS  ${name}`);
  } else {
    failed += 1;
    console.log(`  FAIL  ${name}${extra ? ` — ${extra}` : ''}`);
  }
}

function baseInput(overrides = {}) {
  return {
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
    proof_tx: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    ...overrides,
  };
}

async function main() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gk-trap-'));
  const store = new JsonFileSeenStore(path.join(tmpDir, 'seen.json'));
  store.load();
  const prover = new Prover({
    circuitsDir: path.join(__dirname, '..', 'circuits'),
    taskIdMode: 'sha256',
  });
  const isSeen = (tx) => store.hasProofTx(canonicalProofTx(tx));

  // Evaluate + (when provable) prove + verify one case, mirroring the
  // handler flow: decide, record proof_tx after evaluation, then prove.
  async function runCase(name, taskId, input, wantDecision, wantReason) {
    console.log(`\n[${name}]`);
    const outcome = decide(input, isSeen);
    check('decision', outcome.decision === wantDecision,
      `got ${outcome.decision}, want ${wantDecision}`);
    check('reason_code', outcome.reasonCode === wantReason,
      `got ${outcome.reasonCode}, want ${wantReason}`);
    // Record AFTER successful evaluation (handler does the same).
    store.addProofTx(canonicalProofTx(input.proof_tx));

    if (outcome.provable) {
      const circuitInput = prover.buildInput(taskId, outcome.fields, outcome.decision, SECRET);
      const t0 = Date.now();
      const { proof, publicSignals } = await prover.prove(circuitInput);
      const ms = Date.now() - t0;
      proveTimes.push(ms);
      check('proof generated', !!proof && Array.isArray(publicSignals));
      check('public_signals length is 13', publicSignals.length === 13,
        `got ${publicSignals.length}`);
      const ok = await prover.verify(proof, publicSignals);
      check('proof verifies against zkey VK', ok === true);
      console.log(`  (proving took ${ms}ms)`);
    } else {
      check('not provable (no proof attached)', outcome.provable === false);
    }
  }

  console.log('=== Trap matrix (sample numbers from the event page) ===');

  await runCase('1. VALID', 'gk_test_valid',
    baseInput({ proof_tx: '0x1111111111111111111111111111111111111111111111111111111111111111' }),
    'APPROVE', 'VALID_CONDITION');

  await runCase('2. VK_SUBSTITUTION', 'gk_test_vk',
    baseInput({
      proof_vk: OTHER_VK,
      proof_tx: '0x2222222222222222222222222222222222222222222222222222222222222222',
    }),
    'REJECT', 'VK_SUBSTITUTION');

  // PROOF_REUSED needs two evaluations of the same proof_tx.
  console.log('\n[3. PROOF_REUSED — first use]');
  const reusedTx = '0x3333333333333333333333333333333333333333333333333333333333333333';
  const first = decide(baseInput({ proof_tx: reusedTx }), isSeen);
  check('first use approves', first.decision === 'APPROVE' && first.reasonCode === 'VALID_CONDITION');
  store.addProofTx(canonicalProofTx(reusedTx));
  console.log('\n[3. PROOF_REUSED — second use, different task_id]');
  const second = decide(baseInput({ proof_tx: reusedTx }), isSeen);
  check('decision', second.decision === 'REJECT', `got ${second.decision}`);
  check('reason_code', second.reasonCode === 'PROOF_REUSED', `got ${second.reasonCode}`);
  check('not provable (no proof attached)', second.provable === false);

  await runCase('4. THRESHOLD_MISMATCH', 'gk_test_threshold',
    baseInput({
      public_balance: '500',
      proof_tx: '0x4444444444444444444444444444444444444444444444444444444444444444',
    }),
    'REJECT', 'THRESHOLD_MISMATCH');

  // Boundary: current_block == expiry_block is EXPIRED (>=, not >).
  await runCase('5. EXPIRED_CONDITION (current == expiry)', 'gk_test_expired',
    baseInput({
      current_block: '19842201',
      proof_tx: '0x5555555555555555555555555555555555555555555555555555555555555555',
    }),
    'REJECT', 'EXPIRED_CONDITION');

  await runCase('6. RECIPIENT_MISMATCH', 'gk_test_recipient',
    baseInput({
      recipient: OTHER_ADDR,
      proof_tx: '0x6666666666666666666666666666666666666666666666666666666666666666',
    }),
    'REJECT', 'RECIPIENT_MISMATCH');

  await runCase('7. AMOUNT_OVERFLOW', 'gk_test_amount',
    baseInput({
      amount: '1500',
      proof_tx: '0x7777777777777777777777777777777777777777777777777777777777777777',
    }),
    'REJECT', 'AMOUNT_OVERFLOW');

  console.log('\n=== Boundary checks (decision only, no proving) ===');
  const boundary = (name, input, wantDecision, wantReason) => {
    const o = decide(input, () => false);
    check(`${name} -> ${wantDecision}/${wantReason}`,
      o.decision === wantDecision && o.reasonCode === wantReason,
      `got ${o.decision}/${o.reasonCode}`);
  };
  boundary('current == expiry - 1 approves',
    baseInput({ current_block: '19842200' }), 'APPROVE', 'VALID_CONDITION');
  boundary('public_balance == minimum approves',
    baseInput({ public_balance: '1000' }), 'APPROVE', 'VALID_CONDITION');
  boundary('amount == max_transfer approves',
    baseInput({ amount: '1000' }), 'APPROVE', 'VALID_CONDITION');
  boundary('uppercase proof_vk still matches (case-insensitive)',
    baseInput({ proof_vk: VK.toUpperCase() }), 'APPROVE', 'VALID_CONDITION');
  boundary('mixed formats: numbers + hex strings',
    baseInput({
      minimum: 1000,
      public_balance: '0x5b4', // 1460
      expiry_block: 19842201,
      current_block: 19832000,
      amount: 500,
      max_transfer: '0x3e8', // 1000
    }),
    'APPROVE', 'VALID_CONDITION');

  console.log('\n=== Wrong decisions must be unprovable ===');
  // decision=1 (APPROVE) on the amount-overflow trap: circuit assert throws.
  const overflowInput = baseInput({ amount: '1500' });
  const overflowOutcome = decide(overflowInput, () => false);
  const wrongApprove = prover.buildInput('gk_test_wrong', overflowOutcome.fields, 'APPROVE', SECRET);
  let threw = false;
  try {
    await prover.prove(wrongApprove);
  } catch (err) {
    threw = true;
    console.log(`  (expected throw: ${String(err.message || err).slice(0, 120)})`);
  }
  check('APPROVE on amount-overflow throws (circuit assert)', threw);

  // Informational: is a wrong REJECT on a valid task also unprovable?
  const validOutcome = decide(baseInput(), () => false);
  const wrongReject = prover.buildInput('gk_test_wrong2', validOutcome.fields, 'REJECT', SECRET);
  let rejectThrew = false;
  try {
    await prover.prove(wrongReject);
  } catch {
    rejectThrew = true;
  }
  console.log(`  INFO  REJECT on a valid task ${rejectThrew ? 'throws (circuit is two-way)' : 'PROVES (circuit only constrains APPROVE)'}`);

  console.log('\n=== Proving timings ===');
  if (proveTimes.length > 0) {
    const cold = proveTimes[0];
    const warm = proveTimes.slice(1);
    const warmAvg = warm.length
      ? Math.round(warm.reduce((a, b) => a + b, 0) / warm.length)
      : null;
    console.log(`  cold (first prove): ${cold}ms`);
    console.log(`  warm (avg of ${warm.length}): ${warmAvg === null ? 'n/a' : `${warmAvg}ms`}`);
    console.log(`  all: [${proveTimes.join(', ')}]ms`);
  }

  console.log(`\n=== RESULT: ${passed} passed, ${failed} failed ===`);
  fs.rmSync(tmpDir, { recursive: true, force: true });
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('TRAP MATRIX CRASHED:', err);
  process.exit(1);
});
