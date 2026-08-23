/**
 * Key agreement with the upstream identity provider.
 *
 * Node's crypto module has no ML-KEM yet, so this uses the audited pure-JS
 * implementation from @noble/post-quantum. Session material recorded today
 * would still be worth opening once a CRQC exists.
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

export interface MeshKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** Generate a fresh ML-KEM key pair for this broker. */
export function generate(): MeshKeyPair {
  const keys = ml_kem768.keygen(); //@PS js-l1-mlkem|ML-KEM-768|1|algorithm|upstream key agreement
  return { publicKey: keys.publicKey, secretKey: keys.secretKey };
}

/** Encapsulate a fresh shared secret to a peer's published key. */
export function initiate(peerPublic: Uint8Array): { sharedSecret: Uint8Array; cipherText: Uint8Array } {
  return ml_kem768.encapsulate(peerPublic);
}

/** Recover the shared secret an initiator encapsulated to us. */
export function accept(secretKey: Uint8Array, cipherText: Uint8Array): Uint8Array {
  return ml_kem768.decapsulate(cipherText, secretKey);
}
