/**
 * Session stores.
 *
 * Stores are resolved by the name in the config file, so adding one does not
 * mean touching the broker entry point.
 */

import * as envelope from './envelope.js';

export interface SessionStore {
  put(key: string, value: Buffer): void;
  get(key: string): Buffer | undefined;
}

/** A store that seals every value before it is written. */
export class SealedStore implements SessionStore {
  private readonly items = new Map<string, Buffer>();

  constructor(private readonly dataKey: Buffer) {}

  put(key: string, value: Buffer): void {
    const sealed = envelope.seal(this.dataKey, value, Buffer.from(key)); //@PS js-l3-wrapper|AES-256-GCM|3|algorithm|AEAD reached only through the store registry
    this.items.set(key, envelope.toWire(sealed));
  }

  get(key: string): Buffer | undefined {
    const wire = this.items.get(key);
    if (!wire) return undefined;
    return envelope.open(this.dataKey, envelope.fromWire(wire), Buffer.from(key));
  }
}

type StoreFactory = (dataKey: Buffer) => SessionStore;

/** Store names as they appear in config/broker.yaml. */
export const REGISTRY: Record<string, StoreFactory> = {
  'sealed-memory': (dataKey) => new SealedStore(dataKey),
  'sealed-scratch': (dataKey) => new SealedStore(dataKey),
};

/** Resolve a store by config name. */
export function openStore(name: string, dataKey: Buffer): SessionStore {
  const factory = REGISTRY[name];
  if (!factory) {
    throw new Error(`store: unknown store ${name}`);
  }
  return factory(dataKey); //@PS +js-l3-wrapper
}
