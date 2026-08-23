package io.proofstein.ledger;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import io.proofstein.ledger.config.Settings;
import io.proofstein.ledger.crypto.Envelope;
import io.proofstein.ledger.crypto.Fingerprint;
import io.proofstein.ledger.crypto.Identity;
import io.proofstein.ledger.crypto.Kem;
import io.proofstein.ledger.store.SegmentStore;

/** ledger-svc entry point: seals one ledger block and signs it. */
public final class App {

    private App() {
    }

    public static void main(String[] args) throws Exception {
        Path configPath = args.length > 0 ? Path.of(args[0]) : null;
        Settings settings = Settings.load(configPath);

        Identity identity = Identity.generate();
        byte[] dataKey = Envelope.newDataKey();
        SegmentStore.Store store = SegmentStore.open(settings.store(), dataKey);

        byte[] block = "ledger: seq=41822 debit=EUR 1204.55 credit=EUR 1204.55 account=DE89370400440532013000"
                .getBytes(StandardCharsets.UTF_8);

        String reference = Fingerprint.of(block);
        store.put(reference, block);

        byte[] signature = identity.signBlock(block);
        String replicationAlgorithm = replicationAlgorithm();

        System.out.printf(
                "node ready store=%s cipher=%s fingerprint=%s sig=%dB thumbprint=%d replication=%s%n",
                settings.store(),
                settings.segmentCipher(),
                Fingerprint.shortForm(reference),
                signature.length,
                identity.peerThumbprint().length,
                replicationAlgorithm);
    }

    /**
     * Resolve the replication key agreement, which needs a Java 24 or newer
     * runtime. The build targets 21, so a node on an older JRE still starts and
     * simply replicates over the classical group instead.
     */
    private static String replicationAlgorithm() {
        try {
            return Kem.generate().algorithm();
        } catch (Exception e) {
            return "unavailable (" + e.getClass().getSimpleName() + ")";
        }
    }
}
