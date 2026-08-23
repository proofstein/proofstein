package io.proofstein.ledger.crypto;

import static java.security.KeyPairGenerator.getInstance;
import static org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec.sha2_128s;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

/**
 * Post-quantum block signatures.
 *
 * <p>Blocks are signed on the hot path and verified by every peer, so the
 * signing scheme is chosen for verification cost rather than for key size. The
 * lattice scheme is the default; the hash-based one is kept available for
 * deployments that will not accept a lattice assumption, and the compact
 * lattice scheme for the bandwidth-constrained edge nodes.
 *
 * <p>Unlike {@link AuditSeal}, none of these is stateful: a key here signs an
 * unbounded number of blocks and needs no index tracking.
 */
public final class BlockSeal {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private BlockSeal() {
    }

    /** Default block signing key. */
    public static KeyPair lattice() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-DSA", "BC");
        generator.initialize(org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_65);
        return generator.generateKeyPair();
    }

    /** For deployments that decline the lattice assumption. */
    public static KeyPair hashBased() throws GeneralSecurityException {
        KeyPairGenerator generator = getInstance("SLH-DSA", "BC");
        generator.initialize(new SPHINCSPlusParameterSpec(sha2_128s.getName()));
        return generator.generateKeyPair();
    }

    /** For edge nodes where signature size dominates the link budget. */
    public static KeyPair compact() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Falcon", "BC");
        generator.initialize(FalconParameterSpec.falcon_512);
        return generator.generateKeyPair();
    }
}
