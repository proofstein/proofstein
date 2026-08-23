package io.proofstein.ledger.store;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import io.proofstein.ledger.crypto.Envelope;

/**
 * Ledger segment stores.
 *
 * <p>Stores are resolved by the name in application.properties and reached
 * through the registry below, so adding one does not mean touching the service.
 */
public final class SegmentStore {

    /** What the service needs from a segment store. */
    public interface Store {
        void put(String key, byte[] value) throws GeneralSecurityException;

        byte[] get(String key) throws GeneralSecurityException;
    }

    /** A store that seals every segment before it is written. */
    public static final class Sealed implements Store {
        private final Map<String, byte[]> items = new HashMap<>();
        private final Envelope envelope;

        Sealed(byte[] dataKey) {
            this.envelope = new Envelope(dataKey);
        }

        @Override
        public void put(String key, byte[] value) throws GeneralSecurityException {
            items.put(key, envelope.seal(value, key.getBytes(StandardCharsets.UTF_8)));
        }

        @Override
        public byte[] get(String key) throws GeneralSecurityException {
            byte[] wire = items.get(key);
            return wire == null ? null : envelope.open(wire, key.getBytes(StandardCharsets.UTF_8));
        }
    }

    /** Store names as they appear in application.properties. */
    private static final Map<String, Function<byte[], Store>> REGISTRY = Map.of(
            "sealed-memory", Sealed::new,
            "sealed-scratch", Sealed::new);

    private SegmentStore() {
    }

    /** Resolve a store by config name. */
    public static Store open(String name, byte[] dataKey) {
        Function<byte[], Store> factory = REGISTRY.get(name);
        if (factory == null) {
            throw new IllegalArgumentException("store: unknown store " + name);
        }
        return factory.apply(dataKey);
    }
}
