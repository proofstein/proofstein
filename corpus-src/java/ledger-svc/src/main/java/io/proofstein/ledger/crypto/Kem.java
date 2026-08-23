package io.proofstein.ledger.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * Key agreement for ledger replication.
 *
 * <p>Replication traffic carries settled balances that stay sensitive for the
 * statutory retention period, so the replication key is agreed post-quantum.
 * Requires a Java 24 or newer runtime; the build targets 21.
 */
public final class Kem {

    private final KeyPair keyPair;

    private Kem(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    /** Generate a fresh replication key pair. */
    public static Kem generate() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-KEM"); //@PS java-l1-mlkem|ML-KEM|1|algorithm|ledger replication key agreement
        return new Kem(generator.generateKeyPair());
    }

    /** Return the encapsulation key published in the replication directory. */
    public byte[] encapsulationKey() {
        return keyPair.getPublic().getEncoded();
    }

    /** Return the algorithm name the provider resolved. */
    public String algorithm() {
        return keyPair.getPublic().getAlgorithm();
    }
}
