'use strict';
/**
 * Field-element helpers for the BN128 (alt_bn128) scalar field used by the
 * gatekeeper Groth16 circuit.
 *
 * Task values arrive as decimal strings, hex strings or numbers; they are
 * normalised to BigInt for the decision logic and reduced mod p (as decimal
 * strings) for the circuit inputs.
 */

const crypto = require('crypto');
const { keccak256 } = require('js-sha3');

// BN128 scalar-field prime.
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Normalise a task value (number, decimal string or 0x-hex string) to a
 * non-negative BigInt. Throws on anything unparseable.
 */
function toBigInt(value, name) {
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(`${name}: expected a non-negative integer, got ${value}`);
    }
    return BigInt(value);
  }
  if (typeof value === 'string') {
    const s = value.trim();
    if (s === '') throw new Error(`${name}: empty string`);
    if (/^0[xX][0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^[0-9]+$/.test(s)) return BigInt(s);
    throw new Error(`${name}: not a decimal or hex number: ${JSON.stringify(value)}`);
  }
  throw new Error(`${name}: unsupported type ${typeof value}`);
}

/** Reduce a BigInt mod p and return it as a decimal string (circuit input). */
function toFieldString(bigintValue) {
  return (bigintValue % FIELD_PRIME).toString();
}

/**
 * Canonical key for a proof_tx in the seen-set: lowercase hex with a 0x
 * prefix. The ORIGINAL value is echoed back in responses; only the key is
 * canonicalised, so "0xAB.." and "0xab.." count as the same proof.
 */
function canonicalProofTx(proofTx) {
  if (typeof proofTx !== 'string' || proofTx.trim() === '') {
    throw new Error('proof_tx: missing or empty');
  }
  const s = proofTx.trim().toLowerCase();
  return s.startsWith('0x') ? s : `0x${s}`;
}

/**
 * Map a string task_id (e.g. "gk_24_9d1") to a circuit field element.
 * The exact mapping the platform expects is NOT documented (open question —
 * see README); the mode is selectable so it can be switched without a
 * redeploy of logic. Default "sha256".
 */
function taskIdToField(taskId, mode) {
  if (typeof taskId !== 'string' || taskId.length === 0) {
    throw new Error('task_id: missing or empty');
  }
  switch (mode) {
    case 'sha256': {
      const digest = crypto.createHash('sha256').update(taskId, 'utf8').digest();
      return toFieldString(BigInt(`0x${digest.toString('hex')}`));
    }
    case 'keccak256': {
      return toFieldString(BigInt(`0x${keccak256(taskId)}`));
    }
    case 'numeric': {
      const digits = taskId.replace(/[^0-9]/g, '');
      if (digits === '') throw new Error('task_id: no digits for numeric TASK_ID_MODE');
      return toFieldString(BigInt(digits));
    }
    case 'hex': {
      const hex = taskId.replace(/[^0-9a-fA-F]/g, '');
      if (hex === '') throw new Error('task_id: no hex chars for hex TASK_ID_MODE');
      return toFieldString(BigInt(`0x${hex}`));
    }
    default:
      throw new Error(`unknown TASK_ID_MODE: ${mode}`);
  }
}

/**
 * Deterministic per-task salt: HMAC-SHA256(secret, "gatekeeper-salt:"+taskId)
 * mod p. Deterministic (not random) so a re-proven task yields the same
 * circuit inputs; the response cache is still what guarantees byte-identical
 * redeliveries (Groth16 proofs themselves are randomised per run).
 */
function saltForTask(secret, taskId) {
  const digest = crypto
    .createHmac('sha256', secret)
    .update(`gatekeeper-salt:${taskId}`, 'utf8')
    .digest();
  return toFieldString(BigInt(`0x${digest.toString('hex')}`));
}

module.exports = {
  FIELD_PRIME,
  toBigInt,
  toFieldString,
  canonicalProofTx,
  taskIdToField,
  saltForTask,
};
