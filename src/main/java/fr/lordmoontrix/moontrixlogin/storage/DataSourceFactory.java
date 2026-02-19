package fr.lordmoontrix.moontrixlogin.storage;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import fr.lordmoontrix.moontrixlogin.config.PluginConfig;
import java.nio.file.Path;

public final class DataSourceFactory {
    private DataSourceFactory() {
    }

    public static HikariDataSource create(PluginConfig.Storage storage, DatabaseType type, Path dataFolder) {
        HikariConfig config = new HikariConfig();
        if (type == DatabaseType.MYSQL) {
            String jdbcUrl = "jdbc:mysql://" + storage.getMysqlHost() + ":" + storage.getMysqlPort()
                + "/" + storage.getMysqlDatabase() + "?useSSL=false&serverTimezone=UTC&cachePrepStmts=true&useServerPrepStmts=true";
            config.setJdbcUrl(jdbcUrl);
            config.setUsername(storage.getMysqlUsername());
            config.setPassword(storage.getMysqlPassword());

            int maxPool = clampPoolSize(storage.getMysqlPoolSize());
            int minIdle = clamp(storage.getMysqlMinimumIdle(), 1, maxPool);

            config.setMaximumPoolSize(maxPool);
            config.setMinimumIdle(minIdle);
            config.setConnectionTimeout(Math.max(2_000L, storage.getMysqlConnectionTimeoutMs()));
            config.setIdleTimeout(Math.max(30_000L, storage.getMysqlIdleTimeoutMs()));
            config.setMaxLifetime(Math.max(60_000L, storage.getMysqlMaxLifetimeMs()));
            config.setKeepaliveTime(60_000L);
            config.setValidationTimeout(3_000L);
            config.setInitializationFailTimeout(5_000L);
            config.addDataSourceProperty("cachePrepStmts", "true");
            config.addDataSourceProperty("prepStmtCacheSize", "250");
            config.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");
            config.addDataSourceProperty("socketTimeout", "20000");
            if (storage.getMysqlLeakDetectionThresholdMs() > 0L) {
                config.setLeakDetectionThreshold(storage.getMysqlLeakDetectionThresholdMs());
            }
        } else {
            String sqlitePath = dataFolder.resolve(storage.getSqliteFile()).toAbsolutePath().toString();
            config.setJdbcUrl("jdbc:sqlite:" + sqlitePath);
            config.setMaximumPoolSize(1);
            config.setMinimumIdle(1);
        }
        config.setPoolName("MoontrixLoginPool");
        config.setRegisterMbeans(true);
        config.setAutoCommit(true);
        return new HikariDataSource(config);
    }

    private static int clampPoolSize(int configuredPoolSize) {
        int cpuBased = Math.max(8, Runtime.getRuntime().availableProcessors() * 4);
        int preferred = configuredPoolSize > 0 ? configuredPoolSize : cpuBased;
        return clamp(preferred, 8, 50);
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }
}


