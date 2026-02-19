package fr.lordmoontrix.moontrixlogin.service;

import fr.lordmoontrix.moontrixlogin.storage.EmailVerificationRecord;
import fr.lordmoontrix.moontrixlogin.storage.EmailVerificationRepository;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public final class VerificationService {
    private final EmailVerificationRepository repository;
    private final int codeLength;
    private final int ttlSeconds;
    private final SecureRandom random = new SecureRandom();

    public VerificationService(EmailVerificationRepository repository, int codeLength, int ttlSeconds) {
        this.repository = repository;
        this.codeLength = codeLength;
        this.ttlSeconds = ttlSeconds;
    }

    public CompletableFuture<String> createCode(UUID uuid, String email) {
        String code = generateCode(codeLength);
        Instant expiresAt = Instant.now().plus(ttlSeconds, ChronoUnit.SECONDS);
        return repository.upsert(uuid, email, code, expiresAt).thenApply(v -> code);
    }

    public CompletableFuture<Optional<EmailVerificationRecord>> get(UUID uuid) {
        return repository.find(uuid);
    }

    public CompletableFuture<Optional<EmailVerificationRecord>> verifyAndConsume(UUID uuid, String code) {
        return repository.find(uuid).thenCompose(optional -> {
            if (!optional.isPresent()) {
                return CompletableFuture.completedFuture(Optional.empty());
            }
            EmailVerificationRecord record = optional.get();
            if (record.getExpiresAt() != null && record.getExpiresAt().isBefore(Instant.now())) {
                return repository.delete(uuid).thenApply(v -> Optional.empty());
            }
            if (!record.getCode().equalsIgnoreCase(code)) {
                return CompletableFuture.completedFuture(Optional.empty());
            }
            return repository.delete(uuid).thenApply(v -> Optional.of(record));
        });
    }

    private String generateCode(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(random.nextInt(10));
        }
        return sb.toString();
    }
}


