package fr.lordmoontrix.moontrixlogin.model;

import java.time.Instant;
import java.util.UUID;

public final class Session {
    private final UUID uuid;
    private AuthState state;
    private Instant lastAuthenticatedAt;
    private String lastIp;

    public Session(UUID uuid, AuthState state) {
        this.uuid = uuid;
        this.state = state;
    }

    public UUID getUuid() {
        return uuid;
    }

    public AuthState getState() {
        return state;
    }

    public void setState(AuthState state) {
        this.state = state;
    }

    public Instant getLastAuthenticatedAt() {
        return lastAuthenticatedAt;
    }

    public void markAuthenticated() {
        this.state = AuthState.AUTHENTICATED;
        this.lastAuthenticatedAt = Instant.now();
    }

    public String getLastIp() {
        return lastIp;
    }

    public void setLastIp(String lastIp) {
        this.lastIp = lastIp;
    }
}
