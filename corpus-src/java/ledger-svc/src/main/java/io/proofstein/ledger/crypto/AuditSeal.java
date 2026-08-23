package io.proofstein.ledger.crypto;

import static org.bouncycastle.pqc.crypto.lms.LMSigParameters.lms_sha256_n32_h10;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.jcajce.spec.LMSKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;

/**
 * Long-term seals over the audit log.
 *
 * <p>An audit segment is sealed once and verified for the statutory retention
 * period, which outlives any signing key we would rotate. The seal is therefore
 * stateful hash-based rather than lattice-based: the security rests on the hash
 * function alone, the parameters bound the number of signatures at key
 * generation, and the private key advances on every use.
 *
 * <p><b>Statefulness is the operational hazard, not the cryptography.</b> Reusing
 * a one-time key index destroys the security of the scheme, so the sealer is a
 * singleton over a single key file and refuses to run where two writers could
 * share it. See {@code docs/audit-seal.md} in the operations handbook.
 */
public final class AuditSeal {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final KeyPair segmentSeal;
    private final KeyPair firmwareSeal;

    private AuditSeal(KeyPair segmentSeal, KeyPair firmwareSeal) {
        this.segmentSeal = segmentSeal;
        this.firmwareSeal = firmwareSeal;
    }

    /**
     * Generate both seal keys.
     *
     * <p>Segment seals use a single tree of height 10, which is 1024 segments
     * before the key is exhausted. roughly eleven months at the current
     * rollover rate. Firmware seals use the two-level scheme, which trades a
     * larger signature for a key that does not need re-provisioning.
     */
    public static AuditSeal generate() throws GeneralSecurityException {
        KeyPairGenerator segment = KeyPairGenerator.getInstance("XMSS", "BC"); //@PS java-l1-xmss|XMSS|1|algorithm|Bouncy Castle XMSS via KeyPairGenerator.getInstance("XMSS", "BC"); stateful hash-based signature
        segment.initialize(new XMSSParameterSpec(10, XMSSParameterSpec.SHA256));

        KeyPairGenerator firmware = KeyPairGenerator.getInstance("LMS", "BC");
        firmware.initialize(
                new LMSKeyGenParameterSpec(lms_sha256_n32_h10, LMOtsParameters.sha256_n32_w4)); //@PS java-l2-lms|LMS|2|algorithm|LMS parameter set lms_sha256_n32_h10 reached through a static import of LMSigParameters

        return new AuditSeal(segment.generateKeyPair(), firmware.generateKeyPair());
    }

    /** Return the public seal published alongside each archived segment. */
    public byte[] segmentSealKey() {
        return segmentSeal.getPublic().getEncoded();
    }

    /** Return the public seal shipped in the firmware manifest. */
    public byte[] firmwareSealKey() {
        return firmwareSeal.getPublic().getEncoded();
    }

    /** Return the algorithm names the provider resolved, for the startup banner. */
    public String describe() {
        return segmentSeal.getPublic().getAlgorithm()
                + " / "
                + firmwareSeal.getPublic().getAlgorithm();
    }
}
