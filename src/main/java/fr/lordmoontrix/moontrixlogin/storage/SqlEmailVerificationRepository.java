package fr.lordmoontrix.moontrixlogin.storage;

import com.zaxxer.hikari.HikariDataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

public final class SqlEmailVerificationRepository implements EmailVerificationRepository {
    private final HikariDataSource dataSource;
    private final ExecutorService executor;

    public SqlEmailVerificationRepository(HikariDataSource dataSource, ExecutorService executor) {
        this.dataSource = dataSource;
        this.executor = executor;
    }

    @Override
    public CompletableFuture<Void> upsert(UUID uuid, String email, String code, Instant expiresAt) {
        return CompletableFuture.runAsync(() -> {
            String sql = "REPLACE INTO ml_email_verifications (uuid, email, code, expires_at) VALUES (?, ?, ?, ?)";
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, uuid.toString());
                ps.setString(2, email);
                ps.setString(3, code);
                ps.setTimestamp(4, Timestamp.from(expiresAt));
                ps.executeUpdate();
            } catch (Exception ex) {
                throw new RuntimeException("Failed to upsert email verification", ex);
            }
        }, executor);
    }

    @Override
    public CompletableFuture<Optional<EmailVerificationRecord>> find(UUID uuid) {
        return CompletableFuture.supplyAsync(() -> {
            String sql = "SELECT uuid, email, code, expires_at FROM ml_email_verifications WHERE uuid = ?";
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, uuid.toString());
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        return Optional.empty();
                    }
                    return Optional.of(new EmailVerificationRecord(
                        UUID.fromString(rs.getString("uuid")),
                        rs.getString("email"),
                        rs.getString("code"),
                        toInstant(rs.getTimestamp("expires_at"))
                    ));
                }
            } catch (Exception ex) {
                throw new RuntimeException("Failed to load email verification", ex);
            }
        }, executor);
    }

    @Override
    public CompletableFuture<Void> delete(UUID uuid) {
        return CompletableFuture.runAsync(() -> {
            String sql = "DELETE FROM ml_email_verifications WHERE uuid = ?";
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, uuid.toString());
                ps.executeUpdate();
            } catch (Exception ex) {
                throw new RuntimeException("Failed to delete email verification", ex);
            }
        }, executor);
    }

    private Instant toInstant(Timestamp ts) {
        return ts == null ? null : ts.toInstant();
    }
}


