/**
 * Session payload sealing.
 *
 * Broker sessions carry short-lived credentials, so every payload is sealed
 * with a fresh nonce under the session's data key.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export const NONCE_BYTES = 12;
export const DATA_KEY_BYTES = 32;
export const TAG_BYTES = 16;

export interface Sealed {
  nonce: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
}

/** Return a fresh data key for one session. */
export function newDataKey(): Buffer {
  return randomBytes(DATA_KEY_BYTES);
}

/** Seal a session payload. */
export function seal(dataKey: Buffer, plaintext: Buffer, associated: Buffer): Sealed {
  if (dataKey.length !== DATA_KEY_BYTES) {
    throw new Error(`envelope: data key must be ${DATA_KEY_BYTES} bytes`);
  }
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', dataKey, nonce);
  cipher.setAAD(associated);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { nonce, ciphertext, tag: cipher.getAuthTag() };
}

/** Reverse {@link seal}. */
export function open(dataKey: Buffer, sealed: Sealed, associated: Buffer): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', dataKey, sealed.nonce);
  decipher.setAAD(associated);
  decipher.setAuthTag(sealed.tag);
  return Buffer.concat([decipher.update(sealed.ciphertext), decipher.final()]);
}

/** Pack a sealed payload for the wire. */
export function toWire(sealed: Sealed): Buffer {
  return Buffer.concat([sealed.nonce, sealed.tag, sealed.ciphertext]);
}

/** Unpack a wire payload. */
export function fromWire(blob: Buffer): Sealed {
  if (blob.length <= NONCE_BYTES + TAG_BYTES) {
    throw new Error('envelope: payload too short');
  }
  return {
    nonce: blob.subarray(0, NONCE_BYTES),
    tag: blob.subarray(NONCE_BYTES, NONCE_BYTES + TAG_BYTES),
    ciphertext: blob.subarray(NONCE_BYTES + TAG_BYTES),
  };
}
