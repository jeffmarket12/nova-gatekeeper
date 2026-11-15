'use strict';
/**
 * Deterministic decision logic for Proof Gatekeeper tasks.
 *
 * The decision mirrors the gatekeeper circuit exactly: every check is a
 * plain field comparison, evaluated in a fixed order, and the agent FAILS
 * CLOSED — any uncertainty becomes a REJECT.
 *
 * Check order and boundary semantics (must match the circuit):
 *   1. proof_vk != registered_vk            -> REJECT VK_SUBSTITUTION
 *   2. proof_tx already seen                -> REJECT PROOF_REUSED (not provable)
 *   3. public_balance < minimum             -> REJECT THRESHOLD_MISMATCH
 *   4. current_block >= expiry_block        -> REJECT EXPIRED_CONDITION
 *                                              (note: >=, not > — a task is
 *                                              expired AT its expiry block)
 *   5. recipient != condition_recipient     -> REJECT RECIPIENT_MISMATCH
 *   6. amount > max_transfer                -> REJECT AMOUNT_OVERFLOW
 *   else                                    -> APPROVE VALID_CONDITION
 *
 * VKs and addresses are compared as VALUES (BigInt), so "0xAB.." and
 * "0xab.." (and leading-zero variants) count as equal.
 *
 * PROOF_REUSED is the only non-provable outcome: there is no proof to attach
 * (the reused proof belongs to an earlier task), so the response carries no
 * proof/public_signals.
 */

const { toBigInt } = require('./field');

function reject(reasonCode, provable) {
  return { decision: 'REJECT', reasonCode, provable };
}

/**
 * Decide a task.
 *
 * @param {object} input  The task's `input` object (raw values).
 * @param {Function} isProofTxSeen  (canonicalProofTx) => boolean.
 * @returns {{decision, reasonCode, provable, fields}}
 *   `fields` holds the normalised BigInt values, reused by the prover so the
 *   circuit inputs are built from exactly the values that were decided on.
 * @throws on malformed input (caller turns this into REJECT / INVALID_TASK).
 */
function decide(input, isProofTxSeen) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('input: missing or not an object');
  }

  // Normalise + validate every field first. Any unparseable value throws
  // and the whole task becomes INVALID_TASK (fail closed).
  const fields = {
    registeredVk: toBigInt(input.registered_vk, 'registered_vk'),
    proofVk: toBigInt(input.proof_vk, 'proof_vk'),
    minimum: toBigInt(input.minimum, 'minimum'),
    publicBalance: toBigInt(input.public_balance, 'public_balance'),
    expiryBlock: toBigInt(input.expiry_block, 'expiry_block'),
    currentBlock: toBigInt(input.current_block, 'current_block'),
    recipient: toBigInt(input.recipient, 'recipient'),
    conditionRecipient: toBigInt(input.condition_recipient, 'condition_recipient'),
    amount: toBigInt(input.amount, 'amount'),
    maxTransfer: toBigInt(input.max_transfer, 'max_transfer'),
  };
  if (typeof input.proof_tx !== 'string' || input.proof_tx.trim() === '') {
    throw new Error('proof_tx: missing or empty');
  }

  // Checks in protocol order.
  if (fields.proofVk !== fields.registeredVk) {
    return { ...reject('VK_SUBSTITUTION', true), fields };
  }
  if (isProofTxSeen(input.proof_tx)) {
    return { ...reject('PROOF_REUSED', false), fields };
  }
  if (fields.publicBalance < fields.minimum) {
    return { ...reject('THRESHOLD_MISMATCH', true), fields };
  }
  if (fields.currentBlock >= fields.expiryBlock) {
    return { ...reject('EXPIRED_CONDITION', true), fields };
  }
  if (fields.recipient !== fields.conditionRecipient) {
    return { ...reject('RECIPIENT_MISMATCH', true), fields };
  }
  if (fields.amount > fields.maxTransfer) {
    return { ...reject('AMOUNT_OVERFLOW', true), fields };
  }
  return { decision: 'APPROVE', reasonCode: 'VALID_CONDITION', provable: true, fields };
}

module.exports = { decide };
