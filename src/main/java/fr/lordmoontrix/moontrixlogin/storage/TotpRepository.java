package fr.lordmoontrix.moontrixlogin.storage;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public interface TotpRepository {
    CompletableFuture<Void> upsert(UUID uuid, String secret, boolean enabled);

    CompletableFuture<Optional<TotpRecord>> find(UUID uuid);

    CompletableFuture<Void> delete(UUID uuid);
}


