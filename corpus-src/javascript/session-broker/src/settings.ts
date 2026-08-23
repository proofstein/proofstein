/**
 * Runtime settings, read from config/broker.yaml.
 *
 * Only the flat `section.key` subset is supported; a full YAML parser is not
 * worth the dependency for a dozen scalars.
 */

import { readFileSync } from 'node:fs';

export interface Settings {
  store: string;
  sessionCipher: string;
  tokenSignature: string;
  upstreamKeyAgreement: string;
  replayHash: string;
  keyFile: string;
  assertionSignature: string;
  lmsBaseUrl: string;
  lmsTenant: string;
}

function readFlatYaml(path: string): Map<string, string> {
  const values = new Map<string, string>();
  let section = '';

  for (const raw of readFileSync(path, 'utf8').split('\n')) {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const separator = trimmed.indexOf(':');
    if (separator < 0) continue;

    const key = trimmed.slice(0, separator).trim();
    const value = trimmed.slice(separator + 1).trim().replace(/^["']|["']$/g, '');

    if (!value) {
      section = key;
      continue;
    }
    if (!/^\s/.test(raw)) section = '';
    values.set(section ? `${section}.${key}` : key, value);
  }
  return values;
}

/** Load broker settings from disk. */
export function load(path: string): Settings {
  const values = readFlatYaml(path);
  return {
    store: values.get('sessions.store') ?? 'sealed-memory',
    sessionCipher: values.get('crypto.session_cipher') ?? '',
    tokenSignature: values.get('crypto.token_signature') ?? '',
    upstreamKeyAgreement: values.get('crypto.upstream_key_agreement') ?? '',
    replayHash: values.get('replay.fingerprint_hash') ?? '',
    keyFile: values.get('crypto.key_file') ?? '',
    assertionSignature: values.get('crypto.assertion_signature') ?? '',
    lmsBaseUrl: values.get('roster.base_url') ?? '',
    lmsTenant: values.get('roster.tenant') ?? '',
  };
}
