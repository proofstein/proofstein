package io.proofstein.ledger.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/**
 * The long-lived keys a ledger node holds.
 *
 * <p>The RSA key backs the settlement export that the clearing house still
 * verifies with a 2016-vintage toolchain. Everything else signs with Ed25519.
 */
public final class Identity {

    private static final int SETTLEMENT_KEY_BITS = 2048;

    private final KeyPair blockSigning;
    private final KeyPair peerMtls;
    private final KeyPair settlementExport;

    private Identity(KeyPair blockSigning, KeyPair peerMtls, KeyPair settlementExport) {
        this.blockSigning = blockSigning;
        this.peerMtls = peerMtls;
        this.settlementExport = settlementExport;
    }

    /** Build a fresh identity. Production nodes load these from the keystore. */
    public static Identity generate() throws GeneralSecurityException {
        KeyPairGenerator blocks = KeyPairGenerator.getInstance("Ed25519"); //@PS java-l1-ed25519|Ed25519|1|algorithm|ledger block signing key
        KeyPairGenerator peers = KeyPairGenerator.getInstance("EC"); //@PS java-l1-ecdsa|ECDSA-P256|1|algorithm|peer mutual TLS key
        peers.initialize(new ECGenParameterSpec("secp256r1"));

        KeyPairGenerator settlement = KeyPairGenerator.getInstance("RSA"); //@PS java-l1-rsa|RSA-2048|1|algorithm|clearing house settlement export key
        settlement.initialize(SETTLEMENT_KEY_BITS);

        return new Identity(blocks.generateKeyPair(), peers.generateKeyPair(), settlement.generateKeyPair());
    }

    /** Sign a sealed ledger block. */
    public byte[] signBlock(byte[] block) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(blockSigning.getPrivate());
        signature.update(block);
        return signature.sign();
    }

    /** Sign a settlement export for the clearing house. */
    public byte[] signSettlement(byte[] export) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA256withRSA"); //@PS java-l1-sha256rsa|RSA-2048|1|algorithm|settlement export signature
        signature.initSign(settlementExport.getPrivate());
        signature.update(export);
        return signature.sign();
    }

    /** Return the thumbprint of the peer certificate's public key. */
    public byte[] peerThumbprint() throws GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256"); //@PS java-l1-sha256|SHA-256|1|algorithm|peer certificate thumbprint
        return digest.digest(peerMtls.getPublic().getEncoded());
    }
}
