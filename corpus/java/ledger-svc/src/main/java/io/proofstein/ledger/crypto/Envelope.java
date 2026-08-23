package io.proofstein.ledger.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Envelope encryption for ledger entries.
 *
 * <p>Entries are sealed before they reach the write-ahead log, so an operator with
 * filesystem access to a replica cannot read balances out of it.
 */
public final class Envelope {

    public static final int NONCE_BYTES = 12;
    public static final int TAG_BITS = 128;
    public static final int DATA_KEY_BYTES = 32;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final SecretKeySpec dataKey;

    public Envelope(byte[] dataKey) {
        if (dataKey.length != DATA_KEY_BYTES) {
            throw new IllegalArgumentException("envelope: data key must be " + DATA_KEY_BYTES + " bytes");
        }
        this.dataKey = new SecretKeySpec(dataKey, "AES");
    }

    /** Return a fresh data key for one ledger segment. */
    public static byte[] newDataKey() {
        byte[] key = new byte[DATA_KEY_BYTES];
        RANDOM.nextBytes(key);
        return key;
    }

    /** Seal a ledger entry, prefixing the nonce. */
    public byte[] seal(byte[] plaintext, byte[] associated) throws GeneralSecurityException {
        byte[] nonce = new byte[NONCE_BYTES];
        RANDOM.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, dataKey, new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(associated);

        byte[] ciphertext = cipher.doFinal(plaintext);
        byte[] sealed = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, sealed, 0, nonce.length);
        System.arraycopy(ciphertext, 0, sealed, nonce.length, ciphertext.length);
        return sealed;
    }

    /** Reverse {@link #seal}. */
    public byte[] open(byte[] sealed, byte[] associated) throws GeneralSecurityException {
        if (sealed.length <= NONCE_BYTES) {
            throw new IllegalArgumentException("envelope: payload too short");
        }
        byte[] nonce = Arrays.copyOfRange(sealed, 0, NONCE_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(sealed, NONCE_BYTES, sealed.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, dataKey, new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(associated);
        return cipher.doFinal(ciphertext);
    }
}
