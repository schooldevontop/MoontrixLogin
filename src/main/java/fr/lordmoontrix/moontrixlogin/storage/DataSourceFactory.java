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
                + "/" + storage.getMysqlDatabase() + "?useSSL=false&serverTimezone=UTC";
            config.setJdbcUrl(jdbcUrl);
            config.setUsername(storage.getMysqlUsername());
            config.setPassword(storage.getMysqlPassword());
            config.setMaximumPoolSize(storage.getMysqlPoolSize());
        } else {
            String sqlitePath = dataFolder.resolve(storage.getSqliteFile()).toAbsolutePath().toString();
            config.setJdbcUrl("jdbc:sqlite:" + sqlitePath);
            config.setMaximumPoolSize(1);
        }
        config.setPoolName("MoontrixLoginPool");
        config.setAutoCommit(true);
        return new HikariDataSource(config);
    }
}
