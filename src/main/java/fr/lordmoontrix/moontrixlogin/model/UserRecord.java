package fr.lordmoontrix.moontrixlogin.model;

import java.time.Instant;
import java.util.UUID;

public final class UserRecord {
    private final UUID uuid;
    private final String username;
    private final String passwordHash;
    private final String email;
    private final String regIp;
    private final String lastIp;
    private final Instant regTime;
    private final Instant lastLogin;

    public UserRecord(UUID uuid, String username, String passwordHash, String email,
                      String regIp, String lastIp, Instant regTime, Instant lastLogin) {
        this.uuid = uuid;
        this.username = username;
        this.passwordHash = passwordHash;
        this.email = email;
        this.regIp = regIp;
        this.lastIp = lastIp;
        this.regTime = regTime;
        this.lastLogin = lastLogin;
    }

    public UUID getUuid() {
        return uuid;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public String getEmail() {
        return email;
    }

    public String getRegIp() {
        return regIp;
    }

    public String getLastIp() {
        return lastIp;
    }

    public Instant getRegTime() {
        return regTime;
    }

    public Instant getLastLogin() {
        return lastLogin;
    }
}


