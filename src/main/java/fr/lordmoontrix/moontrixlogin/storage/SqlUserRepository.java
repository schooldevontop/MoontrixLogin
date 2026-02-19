package fr.lordmoontrix.moontrixlogin.storage;

import com.zaxxer.hikari.HikariDataSource;
import fr.lordmoontrix.moontrixlogin.model.UserRecord;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

public final class SqlUserRepository implements UserRepository {
    private final HikariDataSource dataSource;
    private final ExecutorService executor;

    public SqlUserRepository(HikariDataSource dataSource, ExecutorService executor) {
        this.dataSource = dataSource;
        this.executor = executor;
    }

    @Override
    public CompletableFuture<Optional<UserRecord>> findByUsername(String username) {
        return CompletableFuture.supplyAsync(() -> {
            String sql = "SELECT uuid, username, password, email, reg_ip, last_ip, reg_time, last_login "
                + "FROM ml_users WHERE LOWER(username) = LOWER(?)";
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, username);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        return Optional.empty();
                    }
                    return Optional.of(mapRow(rs));
                }
            } catch (Exception ex) {
                throw new RuntimeException("Failed to query user by username", ex);
            }
        }, executor);
    }

    @Override
    public CompletableFuture<Optional<UserRecord>> findByUuid(UUID uuid) {
        return CompletableFuture.supplyAsync(() -> {
            String sql = "SELECT uuid, username, password, email, reg_ip, last_ip, reg_time, last_login "
                + "FROM ml_users WHERE uuid = ?";
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, uuid.toString());
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        return Optional.empty();
                    }
                    return Optional.of(mapRow(rs));
                }
            } catch (Exception ex) {
                throw new RuntimeException("Failed to query user by uuid", ex);
            }
        }, executor);
    }

    @Override
    public CompletableFuture<Boolean> create(UserRecord record) {
        return CompletableFuture.supplyAsync(() -> {
            String sql = "INSERT INTO ml_users (uuid, username, password, email, reg_ip, last_ip, reg_time, last_login) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, record.getUuid().toString());
                ps.setString(2, record.getUsername());
                ps.setString(3, record.getPasswordHash());
                ps.setString(4, record.getEmail());
                ps.setString(5, record.getRegIp());
                ps.setString(6, record.getLastIp());
                ps.setTimestamp(7, Timestamp.from(record.getRegTime()));
                ps.setTimestamp(8, Timestamp.from(record.getLastLogin()));
                return ps.executeUpdate() > 0;
            } catch (Exception ex) {
                throw new RuntimeException("Failed to create user", ex);
            }
        }, executor);
    }

    @Override
    public CompletableFuture<Boolean> updatePassword(UUID uuid, String passwordHash) {
        return CompletableFuture.supplyAsync(() -> {
            String sql = "UPDATE ml_users SET password = ? WHERE uuid = ?";
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, passwordHash);
                ps.setString(2, uuid.toString());
                return ps.executeUpdate() > 0;
            } catch (Exception ex) {
                throw new RuntimeException("Failed to update password", ex);
            }
        }, executor);
    }

    @Override
    public CompletableFuture<Boolean> updateEmail(UUID uuid, String email) {
        return CompletableFuture.supplyAsync(() -> {
            String sql = "UPDATE ml_users SET email = ? WHERE uuid = ?";
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, email);
                ps.setString(2, uuid.toString());
                return ps.executeUpdate() > 0;
            } catch (Exception ex) {
                throw new RuntimeException("Failed to update email", ex);
            }
        }, executor);
    }

    @Override
    public CompletableFuture<Boolean> updateLastLogin(UUID uuid, String lastIp) {
        return CompletableFuture.supplyAsync(() -> {
            String sql = "UPDATE ml_users SET last_ip = ?, last_login = ? WHERE uuid = ?";
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, lastIp);
                ps.setTimestamp(2, Timestamp.from(Instant.now()));
                ps.setString(3, uuid.toString());
                return ps.executeUpdate() > 0;
            } catch (Exception ex) {
                throw new RuntimeException("Failed to update last login", ex);
            }
        }, executor);
    }

    @Override
    public CompletableFuture<Boolean> delete(UUID uuid) {
        return CompletableFuture.supplyAsync(() -> {
            String sql = "DELETE FROM ml_users WHERE uuid = ?";
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, uuid.toString());
                return ps.executeUpdate() > 0;
            } catch (Exception ex) {
                throw new RuntimeException("Failed to delete user", ex);
            }
        }, executor);
    }

    private UserRecord mapRow(ResultSet rs) throws Exception {
        UUID uuid = UUID.fromString(rs.getString("uuid"));
        String username = rs.getString("username");
        String password = rs.getString("password");
        String email = rs.getString("email");
        String regIp = rs.getString("reg_ip");
        String lastIp = rs.getString("last_ip");
        Instant regTime = toInstant(rs.getTimestamp("reg_time"));
        Instant lastLogin = toInstant(rs.getTimestamp("last_login"));
        return new UserRecord(uuid, username, password, email, regIp, lastIp, regTime, lastLogin);
    }

    private Instant toInstant(Timestamp ts) {
        return ts == null ? null : ts.toInstant();
    }
}


