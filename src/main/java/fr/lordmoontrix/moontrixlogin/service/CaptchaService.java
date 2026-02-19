package fr.lordmoontrix.moontrixlogin.service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class CaptchaService {
    private final SecureRandom random = new SecureRandom();
    private final int length;
    private final int ttlSeconds;
    private final Map<UUID, CaptchaRecord> pending = new ConcurrentHashMap<>();

    public CaptchaService(int length, int ttlSeconds) {
        this.length = length;
        this.ttlSeconds = ttlSeconds;
    }

    public String create(UUID uuid) {
        String code = generate(length);
        pending.put(uuid, new CaptchaRecord(code, Instant.now().plusSeconds(ttlSeconds)));
        return code;
    }

    public boolean verify(UUID uuid, String code) {
        CaptchaRecord record = pending.get(uuid);
        if (record == null) {
            return false;
        }
        if (record.expiresAt.isBefore(Instant.now())) {
            pending.remove(uuid);
            return false;
        }
        if (!record.code.equalsIgnoreCase(code)) {
            return false;
        }
        pending.remove(uuid);
        return true;
    }

    public boolean hasPending(UUID uuid) {
        CaptchaRecord record = pending.get(uuid);
        return record != null && record.expiresAt.isAfter(Instant.now());
    }

    public void clear(UUID uuid) {
        pending.remove(uuid);
    }

    private String generate(int len) {
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(random.nextInt(10));
        }
        return sb.toString();
    }

    private static final class CaptchaRecord {
        private final String code;
        private final Instant expiresAt;

        private CaptchaRecord(String code, Instant expiresAt) {
            this.code = code;
            this.expiresAt = expiresAt;
        }
    }
}


