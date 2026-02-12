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
        this.executor = Executors.newFixedThreadPool(Math.max(2, storageConfig.getMysqlPoolSize()));
        this.userRepository = new SqlUserRepository(dataSource, executor);
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

    // schema is handled by MigrationRunner
}
