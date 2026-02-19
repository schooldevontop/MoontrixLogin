package fr.lordmoontrix.moontrixlogin.storage;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import fr.lordmoontrix.moontrixlogin.model.UserRecord;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public final class CachedUserRepository implements UserRepository {
    private final UserRepository delegate;
    private final Cache<UUID, Optional<UserRecord>> byUuid;
    private final Cache<String, Optional<UserRecord>> byUsername;

    public CachedUserRepository(UserRepository delegate, int ttlSeconds, int maxEntries) {
        this.delegate = delegate;
        Duration ttl = Duration.ofSeconds(Math.max(5, ttlSeconds));
        long boundedSize = Math.max(100L, maxEntries);
        this.byUuid = Caffeine.newBuilder().expireAfterWrite(ttl).maximumSize(boundedSize).build();
        this.byUsername = Caffeine.newBuilder().expireAfterWrite(ttl).maximumSize(boundedSize).build();
    }

    @Override
    public CompletableFuture<Optional<UserRecord>> findByUsername(String username) {
        String key = normalizeUsername(username);
        Optional<UserRecord> cached = byUsername.getIfPresent(key);
        if (cached != null) {
            return CompletableFuture.completedFuture(cached);
        }
        return delegate.findByUsername(username).thenApply(result -> {
            byUsername.put(key, result);
            result.ifPresent(record -> byUuid.put(record.getUuid(), Optional.of(record)));
            return result;
        });
    }

    @Override
    public CompletableFuture<Optional<UserRecord>> findByUuid(UUID uuid) {
        Optional<UserRecord> cached = byUuid.getIfPresent(uuid);
        if (cached != null) {
            return CompletableFuture.completedFuture(cached);
        }
        return delegate.findByUuid(uuid).thenApply(result -> {
            byUuid.put(uuid, result);
            result.ifPresent(record -> byUsername.put(normalizeUsername(record.getUsername()), Optional.of(record)));
            return result;
        });
    }

    @Override
    public CompletableFuture<Boolean> create(UserRecord record) {
        return delegate.create(record).thenApply(created -> {
            if (created) {
                cacheRecord(record);
            }
            return created;
        });
    }

    @Override
    public CompletableFuture<Boolean> updatePassword(UUID uuid, String passwordHash) {
        return delegate.updatePassword(uuid, passwordHash).thenApply(updated -> {
            if (updated) {
                updateCached(uuid, existing -> new UserRecord(
                    existing.getUuid(),
                    existing.getUsername(),
                    passwordHash,
                    existing.getEmail(),
                    existing.getRegIp(),
                    existing.getLastIp(),
                    existing.getRegTime(),
                    existing.getLastLogin()
                ));
            }
            return updated;
        });
    }

    @Override
    public CompletableFuture<Boolean> updateEmail(UUID uuid, String email) {
        return delegate.updateEmail(uuid, email).thenApply(updated -> {
            if (updated) {
                updateCached(uuid, existing -> new UserRecord(
                    existing.getUuid(),
                    existing.getUsername(),
                    existing.getPasswordHash(),
                    email,
                    existing.getRegIp(),
                    existing.getLastIp(),
                    existing.getRegTime(),
                    existing.getLastLogin()
                ));
            }
            return updated;
        });
    }

    @Override
    public CompletableFuture<Boolean> updateLastLogin(UUID uuid, String lastIp) {
        return delegate.updateLastLogin(uuid, lastIp).thenApply(updated -> {
            if (updated) {
                updateCached(uuid, existing -> new UserRecord(
                    existing.getUuid(),
                    existing.getUsername(),
                    existing.getPasswordHash(),
                    existing.getEmail(),
                    existing.getRegIp(),
                    lastIp,
                    existing.getRegTime(),
                    Instant.now()
                ));
            }
            return updated;
        });
    }

    @Override
    public CompletableFuture<Boolean> delete(UUID uuid) {
        return delegate.delete(uuid).thenApply(deleted -> {
            if (deleted) {
                invalidateByUuid(uuid);
            }
            return deleted;
        });
    }

    private void updateCached(UUID uuid, java.util.function.Function<UserRecord, UserRecord> updater) {
        Optional<UserRecord> current = byUuid.getIfPresent(uuid);
        if (current != null && current.isPresent()) {
            UserRecord updated = updater.apply(current.get());
            cacheRecord(updated);
        } else {
            byUuid.invalidate(uuid);
        }
    }

    private void cacheRecord(UserRecord record) {
        Optional<UserRecord> cached = Optional.of(record);
        byUuid.put(record.getUuid(), cached);
        byUsername.put(normalizeUsername(record.getUsername()), cached);
    }

    private void invalidateByUuid(UUID uuid) {
        Optional<UserRecord> cached = byUuid.getIfPresent(uuid);
        if (cached != null && cached.isPresent()) {
            byUsername.invalidate(normalizeUsername(cached.get().getUsername()));
        }
        byUuid.invalidate(uuid);
    }

    private String normalizeUsername(String username) {
        return username == null ? "" : username.toLowerCase(java.util.Locale.ROOT);
    }
}


