/**
 * Post-quantum attestation signatures over session assertions.
 *
 * A session assertion is signed by the broker and verified by every relying
 * party, so the signing scheme has to be one those parties can verify without
 * a native dependency. All three below are pure JavaScript.
 *
 * The lattice scheme is the default. The hash-based one is offered to relying
 * parties that will not accept a lattice assumption, and the compact lattice
 * scheme where the assertion travels in a header with a size limit.
 */

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { slh_dsa_sha2_128f } from "@noble/post-quantum/slh-dsa";
import { Settings } from "./settings.js";

export type AssertionScheme = "lattice" | "hash-based" | "compact";

export interface SignedAssertion {
  scheme: AssertionScheme;
  payload: Uint8Array;
  signature: Uint8Array;
}

/** Default assertion signer. */
export function signLattice(secretKey: Uint8Array, payload: Uint8Array): SignedAssertion {
  return { scheme: "lattice", payload, signature: ml_dsa65.sign(secretKey, payload) };
}

/** For relying parties that decline the lattice assumption. */
export function signHashBased(secretKey: Uint8Array, payload: Uint8Array): SignedAssertion {
  const signature = slh_dsa_sha2_128f.sign(secretKey, payload);
  return { scheme: "hash-based", payload, signature };
}

/** Resolve the scheme the deployment selected. */
export function schemeFor(settings: Settings): AssertionScheme {
  switch (settings.assertionSignature) {
    case "SLH-DSA-SHA2-128f":
      return "hash-based";
    case "Falcon-512":
      return "compact";
    default:
      return "lattice";
  }
}
