package fr.lordmoontrix.moontrixlogin.storage;

import com.zaxxer.hikari.HikariDataSource;
import fr.lordmoontrix.moontrixlogin.config.PluginConfig;
import java.nio.file.Path;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class StorageManager {
    private final HikariDataSource dataSource;
    private final ExecutorService executor;
    private final UserRepository userRepository;
    private final EmailVerificationRepository emailVerificationRepository;
    private final TotpRepository totpRepository;
    private final PasswordResetRepository passwordResetRepository;

    public StorageManager(PluginConfig.Storage storageConfig, Path dataFolder) {
        DatabaseType type = DatabaseType.from(storageConfig.getType());
        this.dataSource = DataSourceFactory.create(storageConfig, type, dataFolder);

        int workerThreads = type == DatabaseType.SQLITE
            ? 2
            : Math.min(64, Math.max(6, (int) Math.ceil(storageConfig.getMysqlPoolSize() * 0.7)));
        this.executor = Executors.newFixedThreadPool(workerThreads);

        UserRepository sqlUserRepository = new SqlUserRepository(dataSource, executor);
        if (storageConfig.getCache().isEnabled()) {
            this.userRepository = new CachedUserRepository(
                sqlUserRepository,
                storageConfig.getCache().getTtlSeconds(),
                storageConfig.getCache().getMaxEntries()
            );
        } else {
            this.userRepository = sqlUserRepository;
        }

        this.emailVerificationRepository = new SqlEmailVerificationRepository(dataSource, executor);
        this.totpRepository = new SqlTotpRepository(dataSource, executor);
        this.passwordResetRepository = new SqlPasswordResetRepository(dataSource, executor);
        new MigrationRunner(dataSource, type).migrate();
    }

    public UserRepository getUserRepository() {
        return userRepository;
    }

    public ExecutorService getExecutor() {
        return executor;
    }

    public HikariDataSource getDataSource() {
        return dataSource;
    }

    public EmailVerificationRepository getEmailVerificationRepository() {
        return emailVerificationRepository;
    }

    public TotpRepository getTotpRepository() {
        return totpRepository;
    }

    public PasswordResetRepository getPasswordResetRepository() {
        return passwordResetRepository;
    }

    public void shutdown() {
        executor.shutdown();
        dataSource.close();
    }
}
