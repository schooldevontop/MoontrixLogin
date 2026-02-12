package fr.lordmoontrix.moontrixlogin.storage;

import fr.lordmoontrix.moontrixlogin.model.UserRecord;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public interface UserRepository {
    CompletableFuture<Optional<UserRecord>> findByUsername(String username);

    CompletableFuture<Optional<UserRecord>> findByUuid(UUID uuid);

    CompletableFuture<Boolean> create(UserRecord record);

    CompletableFuture<Boolean> updatePassword(UUID uuid, String passwordHash);

    CompletableFuture<Boolean> updateEmail(UUID uuid, String email);

    CompletableFuture<Boolean> updateLastLogin(UUID uuid, String lastIp);

    CompletableFuture<Boolean> delete(UUID uuid);
}
