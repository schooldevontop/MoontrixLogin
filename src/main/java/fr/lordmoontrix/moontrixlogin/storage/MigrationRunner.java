package fr.lordmoontrix.moontrixlogin.storage;

import com.zaxxer.hikari.HikariDataSource;
import fr.lordmoontrix.moontrixlogin.storage.migrations.V1_CreateUsers;
import fr.lordmoontrix.moontrixlogin.storage.migrations.V2_EmailVerification;
import fr.lordmoontrix.moontrixlogin.storage.migrations.V3_Totp;
import fr.lordmoontrix.moontrixlogin.storage.migrations.V4_PasswordReset;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public final class MigrationRunner {
    private final HikariDataSource dataSource;
    private final DatabaseType type;
    private final List<Migration> migrations = new ArrayList<>();

    public MigrationRunner(HikariDataSource dataSource, DatabaseType type) {
        this.dataSource = dataSource;
        this.type = type;
        migrations.add(new V1_CreateUsers());
        migrations.add(new V2_EmailVerification());
        migrations.add(new V3_Totp());
        migrations.add(new V4_PasswordReset());
        migrations.sort(Comparator.comparingInt(Migration::version));
    }

    public void migrate() {
        ensureSchemaTable();
        int current = currentVersion();
        for (Migration migration : migrations) {
            if (migration.version() > current) {
                apply(migration);
                updateVersion(migration.version());
                current = migration.version();
            }
        }
    }

    private void ensureSchemaTable() {
        String sql = "CREATE TABLE IF NOT EXISTS ml_schema_version (version INTEGER NOT NULL)";
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            try (ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM ml_schema_version")) {
                if (rs.next() && rs.getInt(1) == 0) {
                    stmt.execute("INSERT INTO ml_schema_version (version) VALUES (0)");
                }
            }
        } catch (Exception ex) {
            throw new RuntimeException("Failed to ensure schema table", ex);
        }
    }

    private int currentVersion() {
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT version FROM ml_schema_version LIMIT 1")) {
            if (rs.next()) {
                return rs.getInt(1);
            }
            return 0;
        } catch (Exception ex) {
            throw new RuntimeException("Failed to read schema version", ex);
        }
    }

    private void apply(Migration migration) {
        String sql = type == DatabaseType.MYSQL ? migration.mysqlSql() : migration.sqliteSql();
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to apply migration " + migration.version(), ex);
        }
    }

    private void updateVersion(int version) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement("UPDATE ml_schema_version SET version = ?")) {
            ps.setInt(1, version);
            ps.executeUpdate();
        } catch (Exception ex) {
            throw new RuntimeException("Failed to update schema version", ex);
        }
    }
}
