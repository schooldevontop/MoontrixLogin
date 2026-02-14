package fr.lordmoontrix.moontrixlogin.service;

import fr.lordmoontrix.moontrixlogin.crypto.PasswordHasher;
import fr.lordmoontrix.moontrixlogin.model.AuthState;
import fr.lordmoontrix.moontrixlogin.model.UserRecord;
import fr.lordmoontrix.moontrixlogin.security.BruteForceProtector;
import fr.lordmoontrix.moontrixlogin.security.PasswordPolicy;
import fr.lordmoontrix.moontrixlogin.session.SessionManager;
import fr.lordmoontrix.moontrixlogin.storage.UserRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public final class AuthService {
    private final UserRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final BruteForceProtector bruteForceProtector;
    private final SessionManager sessionManager;
    private final MessageService messages;
    private final PasswordPolicy passwordPolicy;

    public AuthService(UserRepository userRepository,
                       PasswordHasher passwordHasher,
                       BruteForceProtector bruteForceProtector,
                       SessionManager sessionManager,
                       MessageService messages,
                       PasswordPolicy passwordPolicy) {
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
        this.bruteForceProtector = bruteForceProtector;
        this.sessionManager = sessionManager;
        this.messages = messages;
        this.passwordPolicy = passwordPolicy;
    }

    public CompletableFuture<AuthResult> register(UUID uuid, String username, String password, String ip) {
        return userRepository.findByUuid(uuid).thenCompose(existingByUuid -> {
            if (existingByUuid.isPresent()) {
                return CompletableFuture.completedFuture(AuthResult.fail(
                    messages.get("registration.name_taken", "Account already registered.")));
            }
            return userRepository.findByUsername(username).thenCompose(existing -> {
                if (existing.isPresent()) {
                    return CompletableFuture.completedFuture(AuthResult.fail(
                        messages.get("registration.name_taken", "Account already registered.")));
                }
                PasswordPolicy.Result policyResult = passwordPolicy.validate(password);
                if (policyResult != PasswordPolicy.Result.OK) {
                    return CompletableFuture.completedFuture(AuthResult.fail(
                        passwordPolicyMessage(policyResult)));
                }
                String hash = passwordHasher.hash(password.toCharArray());
                UserRecord record = new UserRecord(uuid, username, hash, null, ip, ip, Instant.now(), Instant.now());
                return userRepository.create(record).thenApply(created -> {
                    if (created) {
                        sessionManager.markAuthenticated(uuid, ip);
                        return AuthResult.ok(messages.get("registration.success", "Registered successfully."));
                    }
                    return AuthResult.fail(messages.get("error.unexpected_error", "Unexpected error."));
                });
            });
        });
    }

    public CompletableFuture<AuthResult> verifyPassword(UUID uuid, String username, String password, String ip,
                                                        String fingerprint) {
        String ipKey = "IP:" + ip;
        String userKey = "UUID:" + uuid;
        String fingerprintKey = "FP:" + fingerprint;
        if (bruteForceProtector.isLocked(ipKey)
            || bruteForceProtector.isLocked(userKey)
            || bruteForceProtector.isLocked(fingerprintKey)) {
            long remaining = Math.max(
                bruteForceProtector.lockRemainingMillis(ipKey),
                Math.max(
                    bruteForceProtector.lockRemainingMillis(userKey),
                    bruteForceProtector.lockRemainingMillis(fingerprintKey)
                )
            );
            return CompletableFuture.completedFuture(AuthResult.fail(
                messages.get("error.login_wait", "Too many attempts. Try again in " + (remaining / 1000) + "s.")));
        }

        return userRepository.findByUsername(username).thenCompose(existing -> {
            if (existing.isEmpty()) {
                return CompletableFuture.completedFuture(AuthResult.fail(AuthResult.Code.UNREGISTERED,
                    messages.get("error.unregistered_user", "User not registered.")));
            }
            UserRecord record = existing.get();
            boolean ok = passwordHasher.verify(password.toCharArray(), record.getPasswordHash());
            if (!ok) {
                bruteForceProtector.recordFailure(ipKey);
                bruteForceProtector.recordFailure(userKey);
                bruteForceProtector.recordFailure(fingerprintKey);
                if (bruteForceProtector.isLockedNow(ipKey)
                    || bruteForceProtector.isLockedNow(userKey)
                    || bruteForceProtector.isLockedNow(fingerprintKey)) {
                    return CompletableFuture.completedFuture(AuthResult.fail(AuthResult.Code.LOCKED,
                        messages.get("error.login_wait", "Too many attempts. Please wait.")));
                }
                return CompletableFuture.completedFuture(AuthResult.fail(AuthResult.Code.WRONG_PASSWORD,
                    messages.get("login.wrong_password", "Wrong password.")));
            }
            bruteForceProtector.recordSuccess(ipKey);
            bruteForceProtector.recordSuccess(userKey);
            bruteForceProtector.recordSuccess(fingerprintKey);
            return CompletableFuture.completedFuture(AuthResult.ok("PASSWORD_OK"));
        });
    }

    public CompletableFuture<AuthResult> completeLogin(UUID uuid, String ip, String fingerprint) {
        return userRepository.updateLastLogin(uuid, ip).thenApply(updated -> {
            sessionManager.markAuthenticated(uuid, ip, fingerprint);
            return AuthResult.ok(messages.get("login.success", "Logged in."));
        });
    }

    public CompletableFuture<AuthResult> changePassword(UUID uuid, String oldPassword, String newPassword) {
        return userRepository.findByUuid(uuid).thenCompose(existing -> {
            if (existing.isEmpty()) {
                return CompletableFuture.completedFuture(AuthResult.fail(
                    messages.get("error.unregistered_user", "User not registered.")));
            }
            UserRecord record = existing.get();
            if (!passwordHasher.verify(oldPassword.toCharArray(), record.getPasswordHash())) {
                return CompletableFuture.completedFuture(AuthResult.fail(
                    messages.get("password.match_error", "Password mismatch.")));
            }
            PasswordPolicy.Result policyResult = passwordPolicy.validate(newPassword);
            if (policyResult != PasswordPolicy.Result.OK) {
                return CompletableFuture.completedFuture(AuthResult.fail(
                    passwordPolicyMessage(policyResult)));
            }
            String newHash = passwordHasher.hash(newPassword.toCharArray());
            return userRepository.updatePassword(uuid, newHash)
                .thenApply(updated -> updated
                    ? AuthResult.ok(messages.get("misc.password_changed", "Password changed."))
                    : AuthResult.fail(messages.get("error.unexpected_error", "Unexpected error.")));
        });
    }

    public CompletableFuture<AuthResult> unregister(UUID uuid, String password) {
        return userRepository.findByUuid(uuid).thenCompose(existing -> {
            if (existing.isEmpty()) {
                return CompletableFuture.completedFuture(AuthResult.fail(
                    messages.get("error.unregistered_user", "User not registered.")));
            }
            UserRecord record = existing.get();
            if (!passwordHasher.verify(password.toCharArray(), record.getPasswordHash())) {
                return CompletableFuture.completedFuture(AuthResult.fail(
                    messages.get("password.match_error", "Password mismatch.")));
            }
            return userRepository.delete(uuid)
                .thenApply(updated -> updated
                    ? AuthResult.ok(messages.get("unregister.success", "Account unregistered."))
                    : AuthResult.fail(messages.get("error.unexpected_error", "Unexpected error.")));
        });
    }

    public Optional<AuthState> currentState(UUID uuid) {
        return sessionManager.get(uuid).map(session -> session.getState());
    }

    private String passwordPolicyMessage(PasswordPolicy.Result result) {
        switch (result) {
            case TOO_SHORT:
            case TOO_LONG:
                return messages.get("password.wrong_length", "Password length is invalid.");
            case BLACKLISTED:
                return messages.get("password.blacklisted", "Password is not allowed.");
            case MISSING_REQUIRED:
            default:
                return messages.get("password.unsafe_password", "Password does not meet security requirements.");
        }
    }
}
