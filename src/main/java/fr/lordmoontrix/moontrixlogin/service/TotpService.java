package fr.lordmoontrix.moontrixlogin.service;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import fr.lordmoontrix.moontrixlogin.storage.TotpRecord;
import fr.lordmoontrix.moontrixlogin.storage.TotpRepository;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public final class TotpService {
    private final TotpRepository repository;
    private final GoogleAuthenticator authenticator = new GoogleAuthenticator();

    public TotpService(TotpRepository repository) {
        this.repository = repository;
    }

    public CompletableFuture<String> beginSetup(UUID uuid) {
        GoogleAuthenticatorKey key = authenticator.createCredentials();
        return repository.upsert(uuid, key.getKey(), false).thenApply(v -> key.getKey());
    }

    public CompletableFuture<Boolean> confirm(UUID uuid, int code) {
        return repository.find(uuid).thenCompose(optional -> {
            if (optional.isEmpty()) {
                return CompletableFuture.completedFuture(false);
            }
            TotpRecord record = optional.get();
            boolean ok = authenticator.authorize(record.getSecret(), code);
            if (!ok) {
                return CompletableFuture.completedFuture(false);
            }
            return repository.upsert(uuid, record.getSecret(), true).thenApply(v -> true);
        });
    }

    public CompletableFuture<Boolean> disable(UUID uuid) {
        return repository.delete(uuid).thenApply(v -> true);
    }

    public CompletableFuture<Boolean> validate(UUID uuid, int code) {
        return repository.find(uuid).thenApply(optional -> {
            if (optional.isEmpty() || !optional.get().isEnabled()) {
                return false;
            }
            return authenticator.authorize(optional.get().getSecret(), code);
        });
    }

    public CompletableFuture<Optional<TotpRecord>> get(UUID uuid) {
        return repository.find(uuid);
    }
}
