'use strict';
/**
 * Groth16 proving for the gatekeeper circuit (snarkjs).
 *
 * Circuit inputs (13, all decimal strings):
 *   taskId, registeredVkHash, proofVkHash, minimum, publicBalance,
 *   expiryBlock, currentBlock, recipient, conditionRecipient, amount,
 *   maxTransfer, decision ("1" = APPROVE, "0" = REJECT), salt (private).
 *
 * The circuit has 13 public signals: the 12 non-salt inputs (in the order
 * above, taskId last) plus a salt commitment as signal 0. The proof and the
 * public signals are passed through to the platform verbatim; the platform
 * re-verifies them against its own registered verification key.
 *
 * A wrong decision is UNPROVABLE: the circuit asserts the decision matches
 * the checks, so fullProve throws and the caller must fail closed (see
 * handler.js). That throw is a feature, not a bug — it is the circuit acting
 * as referee.
 */

const path = require('path');
const snarkjs = require('snarkjs');
const { toFieldString, taskIdToField, saltForTask } = require('./field');

class Prover {
  constructor({ circuitsDir, taskIdMode }) {
    this.wasmPath = path.join(circuitsDir, 'gatekeeper.wasm');
    this.zkeyPath = path.join(circuitsDir, 'gatekeeper_final.zkey');
    this.taskIdMode = taskIdMode;
    this._verificationKey = null;
  }

  /**
   * Build the 13 circuit inputs from a task. `fields` are the normalised
   * BigInts returned by decide() — the proof is generated from exactly the
   * values the decision was made on.
   */
  buildInput(taskId, fields, decision, secret) {
    return {
      taskId: taskIdToField(taskId, this.taskIdMode),
      registeredVkHash: toFieldString(fields.registeredVk),
      proofVkHash: toFieldString(fields.proofVk),
      minimum: toFieldString(fields.minimum),
      publicBalance: toFieldString(fields.publicBalance),
      expiryBlock: toFieldString(fields.expiryBlock),
      currentBlock: toFieldString(fields.currentBlock),
      recipient: toFieldString(fields.recipient),
      conditionRecipient: toFieldString(fields.conditionRecipient),
      amount: toFieldString(fields.amount),
      maxTransfer: toFieldString(fields.maxTransfer),
      decision: decision === 'APPROVE' ? '1' : '0',
      salt: saltForTask(secret, taskId),
    };
  }

  /** Generate {proof, publicSignals}. Throws when the circuit asserts fail. */
  async prove(circuitInput) {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInput,
      this.wasmPath,
      this.zkeyPath,
    );
    return { proof, publicSignals };
  }

  /** Lazily export (and cache) the verification key from the .zkey. */
  async getVerificationKey() {
    if (!this._verificationKey) {
      this._verificationKey = await snarkjs.zKey.exportVerificationKey(this.zkeyPath);
    }
    return this._verificationKey;
  }

  /** Local verification (used by the tests; the platform verifies itself). */
  async verify(proof, publicSignals) {
    const vk = await this.getVerificationKey();
    return snarkjs.groth16.verify(vk, publicSignals, proof);
  }
}

module.exports = { Prover };
