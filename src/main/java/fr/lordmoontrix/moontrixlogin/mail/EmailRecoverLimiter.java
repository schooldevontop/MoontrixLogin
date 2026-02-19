package fr.lordmoontrix.moontrixlogin.mail;

import java.util.Locale;
import java.util.UUID;

public final class EmailRecoverLimiter {
    private final EmailRateLimiter byUuid;
    private final EmailRateLimiter byEmail;

    public EmailRecoverLimiter(int maxPerWindow, int windowSeconds, int cooldownSeconds) {
        this.byUuid = new EmailRateLimiter(maxPerWindow, windowSeconds, cooldownSeconds);
        this.byEmail = new EmailRateLimiter(maxPerWindow, windowSeconds, cooldownSeconds);
    }

    public EmailRateLimiter.Result tryAcquire(UUID uuid, String email) {
        EmailRateLimiter.Result uuidResult = byUuid.tryAcquire(uuid.toString());
        EmailRateLimiter.Result emailResult = byEmail.tryAcquire(email.toLowerCase(Locale.ROOT));
        if (uuidResult.isAllowed() && emailResult.isAllowed()) {
            return EmailRateLimiter.Result.allowed();
        }
        long wait = Math.max(uuidResult.getRetryAfterSeconds(), emailResult.getRetryAfterSeconds());
        return EmailRateLimiter.Result.denied(wait);
    }
}


