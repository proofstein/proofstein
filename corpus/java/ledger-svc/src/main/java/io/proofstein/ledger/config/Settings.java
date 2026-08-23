package io.proofstein.ledger.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/** Runtime settings, read from application.properties. */
public final class Settings {

    private final Properties properties;

    private Settings(Properties properties) {
        this.properties = properties;
    }

    /** Load settings from a path, falling back to the packaged defaults. */
    public static Settings load(Path path) throws IOException {
        Properties properties = new Properties();
        if (path != null && Files.exists(path)) {
            try (InputStream in = Files.newInputStream(path)) {
                properties.load(in);
            }
        } else {
            try (InputStream in = Settings.class.getResourceAsStream("/application.properties")) {
                if (in == null) {
                    throw new IOException("settings: packaged application.properties is missing");
                }
                properties.load(in);
            }
        }
        return new Settings(properties);
    }

    public String store() {
        return properties.getProperty("ledger.store", "sealed-memory");
    }

    public String segmentCipher() {
        return properties.getProperty("ledger.crypto.segment-cipher", "");
    }

    public String blockSignature() {
        return properties.getProperty("ledger.crypto.block-signature", "");
    }

    public String replicationKeyAgreement() {
        return properties.getProperty("ledger.crypto.replication-key-agreement", "");
    }

    public String indexHash() {
        return properties.getProperty("ledger.index.fingerprint-hash", "");
    }

    public String keystorePath() {
        return properties.getProperty("ledger.crypto.keystore", "");
    }
}
