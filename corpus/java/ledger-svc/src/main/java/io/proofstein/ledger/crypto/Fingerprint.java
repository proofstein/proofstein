package io.proofstein.ledger.crypto;

import static java.security.MessageDigest.getInstance;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * Content fingerprints for the ledger index.
 *
 * <p>The digest factory is statically imported so the index code reads the same
 * way it did before the move off the vendored hashing helper.
 */
public final class Fingerprint {

    public static final String PREFIX = "lg1";

    private Fingerprint() {
    }

    /** Return the index fingerprint of a ledger entry. */
    public static String of(byte[] entry) throws GeneralSecurityException {
        MessageDigest digest = getInstance("SHA-256");
        return PREFIX + ":" + HexFormat.of().formatHex(digest.digest(entry));
    }

    /** Report whether an entry still carries the recorded fingerprint. */
    public static boolean matches(byte[] entry, String fingerprint) throws GeneralSecurityException {
        return of(entry).equals(fingerprint);
    }

    /** The display form used in log lines. */
    public static String shortForm(String fingerprint) {
        int colon = fingerprint.indexOf(':');
        String digest = colon < 0 ? fingerprint : fingerprint.substring(colon + 1);
        return digest.length() <= 12 ? digest : digest.substring(0, 12);
    }
}
