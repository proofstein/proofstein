/**
 * Broker signing identities.
 *
 * The broker signs session tokens with Ed25519. The RSA key backs the legacy
 * JWKS endpoint that two downstream services still poll, and the P-256 key is
 * used for mutual TLS to the upstream identity provider.
 */

import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';

export interface BrokerIdentity {
  tokenSigning: { publicKey: KeyObject; privateKey: KeyObject };
  legacyJwks: { publicKey: KeyObject; privateKey: KeyObject };
  upstreamMtls: { publicKey: KeyObject; privateKey: KeyObject };
}

/** Build a fresh identity set. Production brokers load these from the keystore. */
export function generate(): BrokerIdentity {
  const tokenSigning = generateKeyPairSync('ed25519'); //@PS js-l1-ed25519|Ed25519|1|algorithm|session token signing key
  const legacyJwks = generateKeyPairSync('rsa', { modulusLength: 2048 }); //@PS js-l1-rsa|RSA-2048|1|algorithm|legacy JWKS endpoint key
  const upstreamMtls = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); //@PS js-l1-ecdsa|ECDSA-P256|1|algorithm|upstream mutual TLS key
  return { tokenSigning, legacyJwks, upstreamMtls };
}

/** Sign a session token body. */
export function signToken(identity: BrokerIdentity, body: Buffer): Buffer {
  return sign(null, body, identity.tokenSigning.privateKey);
}

/** Return the thumbprint published alongside the JWKS document. */
export function jwksThumbprint(identity: BrokerIdentity): string {
  const der = identity.legacyJwks.publicKey.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('base64url'); //@PS js-l1-sha256|SHA-256|1|algorithm|JWKS thumbprint digest
}
