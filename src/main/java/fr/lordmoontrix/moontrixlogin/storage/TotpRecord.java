package fr.lordmoontrix.moontrixlogin.storage;

import java.util.UUID;

public final class TotpRecord {
    private final UUID uuid;
    private final String secret;
    private final boolean enabled;

    public TotpRecord(UUID uuid, String secret, boolean enabled) {
        this.uuid = uuid;
        this.secret = secret;
        this.enabled = enabled;
    }

    public UUID getUuid() {
        return uuid;
    }

    public String getSecret() {
        return secret;
    }

    public boolean isEnabled() {
        return enabled;
    }
}
