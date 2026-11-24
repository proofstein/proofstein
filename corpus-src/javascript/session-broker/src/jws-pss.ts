/**
 * RSA-PSS signing for downstream services that register PS256.
 *
 * Those services verify against the RSA key the legacy JWKS endpoint
 * publishes; the JOSE name they registered selects the signature scheme.
 */

import { constants, sign, type KeyObject } from 'node:crypto';

export const PSS_SIGNERS = {
  PS256: (input: Buffer, key: KeyObject): Buffer => sign('sha256', input, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }), //@PS js-l1-jose-ps256|RSASSA-PSS|1|algorithm|JWS PS256: RSASSA-PSS with SHA-256, selected by its JOSE name
};
