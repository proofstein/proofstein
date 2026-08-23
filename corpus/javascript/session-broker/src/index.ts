/**
 * session-broker entry point.
 *
 * Issues sealed sessions, signs the tokens that reference them, and agrees a
 * key with the upstream identity provider.
 */

import { parseArgs } from 'node:util';

import * as envelope from './envelope.js';
import * as fingerprint from './fingerprint.js';
import * as identity from './identity.js';
import * as kem from './kem.js';
import * as settings from './settings.js';
import { openStore } from './store.js';

const DEFAULT_CONFIG = 'config/broker.yaml';

export function run(configPath: string): number {
  const config = settings.load(configPath);
  const ids = identity.generate();
  const meshKeys = kem.generate();

  const dataKey = envelope.newDataKey();
  const store = openStore(config.store, dataKey);

  const session = Buffer.from(
    JSON.stringify({ sub: 'svc-checkout', scope: ['orders:read'], exp: 1893456000 }),
  );
  const reference = fingerprint.of(session);
  store.put(reference, session);

  const token = Buffer.from(`${reference}.${config.store}`);
  const signature = identity.signToken(ids, token);

  console.log(
    `broker ready store=%s cipher=%s fingerprint=%s sig=%dB thumbprint=%s mesh_key=%dB`,
    config.store,
    config.sessionCipher,
    fingerprint.short(reference),
    signature.length,
    identity.jwksThumbprint(ids).slice(0, 12),
    meshKeys.publicKey.length,
  );
  return 0;
}

function main(): number {
  const { values } = parseArgs({
    options: { config: { type: 'string', default: DEFAULT_CONFIG } },
  });
  return run(values.config as string);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exit(main());
}
