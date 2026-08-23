/**
 * Token fingerprints for the replay cache.
 *
 * The hash import is aliased because the replay cache used a non-standard
 * digest before the 3.0 rewrite and the call sites were left alone.
 */

import { createHash as digest } from 'node:crypto'; //@PS +js-l2-sha256

export const FINGERPRINT_PREFIX = 'sb1';

/** Return the replay-cache fingerprint of a token. */
export function of(token: Buffer): string {
  const hex = digest('sha256').update(token).digest('hex'); //@PS js-l2-sha256|SHA-256|2|algorithm|aliased import: createHash imported as digest
  return `${FINGERPRINT_PREFIX}:${hex}`;
}

/** Report whether a token still carries the recorded fingerprint. */
export function matches(token: Buffer, fingerprint: string): boolean {
  return of(token) === fingerprint;
}

/** The display form used in log lines. */
export function short(fingerprint: string): string {
  return fingerprint.split(':')[1]?.slice(0, 12) ?? '';
}
