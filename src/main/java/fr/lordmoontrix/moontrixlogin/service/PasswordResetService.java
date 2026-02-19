package fr.lordmoontrix.moontrixlogin.service;

import fr.lordmoontrix.moontrixlogin.storage.PasswordResetRecord;
import fr.lordmoontrix.moontrixlogin.storage.PasswordResetRepository;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public final class PasswordResetService {
    private final PasswordResetRepository repository;
    private final int codeLength;
    private final int ttlSeconds;
    private final SecureRandom random = new SecureRandom();

    public PasswordResetService(PasswordResetRepository repository, int codeLength, int ttlSeconds) {
        this.repository = repository;
        this.codeLength = codeLength;
        this.ttlSeconds = ttlSeconds;
    }

    public CompletableFuture<String> create(UUID uuid, String email) {
        String code = generate(codeLength);
        Instant expiresAt = Instant.now().plus(ttlSeconds, ChronoUnit.SECONDS);
        return repository.upsert(uuid, email, code, expiresAt).thenApply(v -> code);
    }

    public CompletableFuture<Optional<PasswordResetRecord>> consumeByCode(String code) {
        return repository.findByCode(code).thenCompose(optional -> {
            if (!optional.isPresent()) {
                return CompletableFuture.completedFuture(Optional.empty());
            }
            PasswordResetRecord record = optional.get();
            if (record.getExpiresAt() != null && record.getExpiresAt().isBefore(Instant.now())) {
                return repository.delete(record.getUuid()).thenApply(v -> Optional.empty());
            }
            return repository.delete(record.getUuid()).thenApply(v -> Optional.of(record));
        });
    }

    private String generate(int len) {
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(random.nextInt(10));
        }
        return sb.toString();
    }
}


