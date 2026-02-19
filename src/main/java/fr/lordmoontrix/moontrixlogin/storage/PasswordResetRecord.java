package fr.lordmoontrix.moontrixlogin.storage;

import java.time.Instant;
import java.util.UUID;

public final class PasswordResetRecord {
    private final UUID uuid;
    private final String email;
    private final String code;
    private final Instant expiresAt;

    public PasswordResetRecord(UUID uuid, String email, String code, Instant expiresAt) {
        this.uuid = uuid;
        this.email = email;
        this.code = code;
        this.expiresAt = expiresAt;
    }

    public UUID getUuid() {
        return uuid;
    }

    public String getEmail() {
        return email;
    }

    public String getCode() {
        return code;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}


