'use strict';
/**
 * HMAC-SHA256 helpers for the Agent Games signed-task protocol.
 *
 * Inbound:  the platform signs every POST body; the signature arrives in the
 *           `x-agent-games-signature` header and MUST be verified against the
 *           raw request body BEFORE the JSON is parsed.
 * Outbound: every 200/400 response body is signed the same way and the
 *           signature is returned in the `x-agent-games-signature` header.
 *
 * The shared secret is used as a raw UTF-8 string (Node's createHmac default
 * for string keys). Outbound signatures are lowercase hex. Inbound signatures
 * are accepted as lowercase/uppercase hex, base64, with an optional
 * "sha256=" prefix. Comparison is constant-time.
 */

const crypto = require('crypto');

/** Lowercase-hex HMAC-SHA256 of a Buffer. */
function signHex(secret, bodyBuffer) {
  return crypto.createHmac('sha256', secret).update(bodyBuffer).digest('hex');
}

/**
 * Parse a signature header value into a 32-byte Buffer, or null when the
 * value is not a recognisable signature encoding.
 */
function parseSignature(value) {
  if (typeof value !== 'string') return null;
  let v = value.trim();
  if (v.toLowerCase().startsWith('sha256=')) v = v.slice('sha256='.length);
  // Hex (64 chars, either case).
  if (/^[0-9a-fA-F]{64}$/.test(v)) return Buffer.from(v, 'hex');
  // Base64 of a 32-byte digest (44 chars, one trailing '=').
  if (/^[A-Za-z0-9+/]{43}=$/.test(v)) {
    const buf = Buffer.from(v, 'base64');
    if (buf.length === 32) return buf;
  }
  return null;
}

/**
 * Verify an inbound signature header against the raw body.
 * Returns false (never throws) for missing, malformed or mismatched values.
 */
function verifySignature(secret, bodyBuffer, headerValue) {
  if (!secret) return false;
  const expected = crypto.createHmac('sha256', secret).update(bodyBuffer).digest();
  const provided = parseSignature(headerValue);
  if (!provided || provided.length !== expected.length) return false;
  return crypto.timingSafeEqual(provided, expected);
}

module.exports = { signHex, parseSignature, verifySignature };
