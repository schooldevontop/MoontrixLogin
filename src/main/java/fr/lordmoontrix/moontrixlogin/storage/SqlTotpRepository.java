package fr.lordmoontrix.moontrixlogin.storage;

import com.zaxxer.hikari.HikariDataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

public final class SqlTotpRepository implements TotpRepository {
    private final HikariDataSource dataSource;
    private final ExecutorService executor;

    public SqlTotpRepository(HikariDataSource dataSource, ExecutorService executor) {
        this.dataSource = dataSource;
        this.executor = executor;
    }

    @Override
    public CompletableFuture<Void> upsert(UUID uuid, String secret, boolean enabled) {
        return CompletableFuture.runAsync(() -> {
            String sql = "REPLACE INTO ml_totp (uuid, secret, enabled) VALUES (?, ?, ?)";
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, uuid.toString());
                ps.setString(2, secret);
                ps.setBoolean(3, enabled);
                ps.executeUpdate();
            } catch (Exception ex) {
                throw new RuntimeException("Failed to upsert totp", ex);
            }
        }, executor);
    }

    @Override
    public CompletableFuture<Optional<TotpRecord>> find(UUID uuid) {
        return CompletableFuture.supplyAsync(() -> {
            String sql = "SELECT uuid, secret, enabled FROM ml_totp WHERE uuid = ?";
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, uuid.toString());
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        return Optional.empty();
                    }
                    return Optional.of(new TotpRecord(
                        UUID.fromString(rs.getString("uuid")),
                        rs.getString("secret"),
                        rs.getBoolean("enabled")
                    ));
                }
            } catch (Exception ex) {
                throw new RuntimeException("Failed to load totp", ex);
            }
        }, executor);
    }

    @Override
    public CompletableFuture<Void> delete(UUID uuid) {
        return CompletableFuture.runAsync(() -> {
            String sql = "DELETE FROM ml_totp WHERE uuid = ?";
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, uuid.toString());
                ps.executeUpdate();
            } catch (Exception ex) {
                throw new RuntimeException("Failed to delete totp", ex);
            }
        }, executor);
    }
}
