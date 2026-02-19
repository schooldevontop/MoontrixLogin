package fr.lordmoontrix.moontrixlogin.storage;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public interface PasswordResetRepository {
    CompletableFuture<Void> upsert(UUID uuid, String email, String code, Instant expiresAt);

    CompletableFuture<Optional<PasswordResetRecord>> findByCode(String code);

    CompletableFuture<Void> delete(UUID uuid);
}


