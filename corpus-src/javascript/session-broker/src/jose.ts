/**
 * JOSE for downstream services.
 *
 * Downstream services name the algorithm they accept, as a JOSE `alg` value in
 * their client registration or JWK, and the broker signs or wraps keys with
 * exactly that algorithm. The value selects the operation here; nothing in the
 * broker configuration does.
 */

import { constants, publicEncrypt, sign, type KeyObject } from 'node:crypto';

import { PSS_SIGNERS } from './jws-pss.js';

export type JwsAlgorithm = 'PS256' | 'ES256';
export type KeyWrapAlgorithm = 'RSA-OAEP-256';

type Signer = (input: Buffer, key: KeyObject) => Buffer;
type KeyWrapper = (contentKey: Buffer, key: KeyObject) => Buffer;

const JWS_SIGNERS: Record<JwsAlgorithm, Signer> = {
  ...PSS_SIGNERS,
  ES256: (input, key) => sign('sha256', input, { key, dsaEncoding: 'ieee-p1363' }), //@PS js-l1-jose-es256|ECDSA-P256|1|algorithm|JWS ES256: ECDSA on P-256 with SHA-256, selected by its JOSE name
};

const KEY_WRAPPERS: Record<KeyWrapAlgorithm, KeyWrapper> = {
  'RSA-OAEP-256': (contentKey, key) => publicEncrypt({ key, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, contentKey), //@PS js-l1-jose-oaep|RSAES-OAEP|1|algorithm|JWE RSA-OAEP-256: RSAES-OAEP with SHA-256, selected by its JOSE name
};

function base64url(data: Buffer | string): string {
  return Buffer.from(data).toString('base64url');
}

/** A compact JWS over `payload`, signed with the algorithm the service named. */
export function signCompact(alg: JwsAlgorithm, key: KeyObject, payload: Buffer): string {
  const header = base64url(JSON.stringify({ alg, typ: 'JWT' }));
  const body = base64url(payload);
  const signature = JWS_SIGNERS[alg](Buffer.from(`${header}.${body}`), key);
  return `${header}.${body}.${base64url(signature)}`;
}

/** A content key wrapped for a service, with the algorithm its JWK names. */
export function wrapContentKey(alg: KeyWrapAlgorithm, key: KeyObject, contentKey: Buffer): string {
  return base64url(KEY_WRAPPERS[alg](contentKey, key));
}
