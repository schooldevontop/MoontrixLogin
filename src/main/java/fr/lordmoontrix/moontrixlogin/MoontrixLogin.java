package fr.lordmoontrix.moontrixlogin;

import fr.lordmoontrix.moontrixlogin.command.ChangePasswordCommand;
import fr.lordmoontrix.moontrixlogin.command.LoginCommand;
import fr.lordmoontrix.moontrixlogin.command.LogoutCommand;
import fr.lordmoontrix.moontrixlogin.command.RegisterCommand;
import fr.lordmoontrix.moontrixlogin.command.RootCommand;
import fr.lordmoontrix.moontrixlogin.command.UnregisterCommand;
import fr.lordmoontrix.moontrixlogin.config.PluginConfig;
import fr.lordmoontrix.moontrixlogin.crypto.BCryptHasher;
import fr.lordmoontrix.moontrixlogin.crypto.PasswordHasher;
import fr.lordmoontrix.moontrixlogin.listener.PlayerConnectionListener;
import fr.lordmoontrix.moontrixlogin.listener.PlayerProtectionListener;
import fr.lordmoontrix.moontrixlogin.mail.EmailService;
import fr.lordmoontrix.moontrixlogin.mail.EmailRateLimiter;
import fr.lordmoontrix.moontrixlogin.mail.EmailRecoverLimiter;
import fr.lordmoontrix.moontrixlogin.security.AntiBotService;
import fr.lordmoontrix.moontrixlogin.security.BruteForceProtector;
import fr.lordmoontrix.moontrixlogin.security.DeviceFingerprintService;
import fr.lordmoontrix.moontrixlogin.security.IpReputationService;
import fr.lordmoontrix.moontrixlogin.service.AuthService;
import fr.lordmoontrix.moontrixlogin.service.CaptchaService;
import fr.lordmoontrix.moontrixlogin.service.MessageService;
import fr.lordmoontrix.moontrixlogin.service.PasswordResetService;
import fr.lordmoontrix.moontrixlogin.service.TotpService;
import fr.lordmoontrix.moontrixlogin.service.VerificationService;
import fr.lordmoontrix.moontrixlogin.session.JwtSessionTokenService;
import fr.lordmoontrix.moontrixlogin.session.SessionManager;
import fr.lordmoontrix.moontrixlogin.storage.StorageManager;
import fr.lordmoontrix.moontrixlogin.util.SchedulerUtil;
import fr.lordmoontrix.moontrixlogin.util.ServerVersionRuntimeCheck;
import java.nio.file.Path;
import java.time.Duration;
import org.bukkit.Bukkit;
import org.bukkit.command.PluginCommand;
import org.bukkit.plugin.java.JavaPlugin;

public final class MoontrixLogin extends JavaPlugin {
    private StorageManager storageManager;
    private SessionManager sessionManager;
    private MessageService messageService;
    private CaptchaService captchaService;
    private EmailService emailService;
    private PasswordResetService passwordResetService;
    private PasswordHasher passwordHasher;
    private AntiBotService antiBotService;
    private PluginConfig pluginConfig;
    private DeviceFingerprintService deviceFingerprintService;
    private JwtSessionTokenService jwtSessionTokenService;
    private IpReputationService ipReputationService;

    @Override
    public void onEnable() {
        ServerVersionRuntimeCheck.logCompatibility(getLogger());

        if (!getDataFolder().exists() && !getDataFolder().mkdirs()) {
            getLogger().warning("Failed to create plugin data folder.");
        }
        saveDefaultConfig();
        if (!getDataFolder().toPath().resolve("messages/messages_en.yml").toFile().exists()) {
            saveResource("messages/messages_en.yml", false);
        }
        saveIfMissing("templates/email_verify.html");
        saveIfMissing("templates/email_recover.html");
        saveIfMissing("templates/email_notice.html");

        PluginConfig config;
        try {
            config = PluginConfig.from(getConfig());
        } catch (IllegalStateException ex) {
            getLogger().severe("Invalid secret configuration: " + ex.getMessage());
            Bukkit.getPluginManager().disablePlugin(this);
            return;
        }
        this.pluginConfig = config;
        Path dataFolder = getDataFolder().toPath();
        storageManager = new StorageManager(config.getStorage(), dataFolder);

        sessionManager = new SessionManager(
            Duration.ofSeconds(config.getSecurity().getSessionTimeoutSeconds()),
            dataFolder,
            config.getSecurity().getJwtSecret(),
            getLogger()
        );
        BruteForceProtector bruteForce = new BruteForceProtector(
            config.getSecurity().getBruteForceMaxAttempts(),
            config.getSecurity().getBruteForceWindowSeconds(),
            config.getSecurity().getBruteForceProgressiveLockSeconds()
        );
        passwordHasher = new BCryptHasher(config.getSecurity().getBcryptCost());
        messageService = new MessageService(this);
        captchaService = new CaptchaService(
            config.getSecurity().getCaptchaCodeLength(),
            config.getSecurity().getCaptchaTtlSeconds()
        );
        ipReputationService = new IpReputationService(config.getAntiBot());
        antiBotService = new AntiBotService(config.getAntiBot(), ipReputationService);
        deviceFingerprintService = new DeviceFingerprintService();
        if (config.getSecurity().isRememberMeEnabled()) {
            try {
                jwtSessionTokenService = new JwtSessionTokenService(
                    config.getSecurity().getJwtSecret(),
                    config.getSecurity().getJwtIssuer(),
                    config.getSecurity().getRememberMeTtlDays()
                );
            } catch (IllegalArgumentException ex) {
                getLogger().severe("Invalid JWT configuration: " + ex.getMessage());
                getLogger().severe("Plugin disabled. Configure security.session.jwt.secret or MOONTRIX_JWT_SECRET.");
                Bukkit.getPluginManager().disablePlugin(this);
                return;
            }
        }
        emailService = new EmailService(config.getMail(), storageManager.getExecutor(), getLogger());
        VerificationService verificationService = new VerificationService(
            storageManager.getEmailVerificationRepository(),
            config.getSecurity().getVerificationCodeLength(),
            config.getSecurity().getVerificationCodeTtlSeconds()
        );
        passwordResetService = new PasswordResetService(
            storageManager.getPasswordResetRepository(),
            config.getSecurity().getVerificationCodeLength(),
            config.getSecurity().getVerificationCodeTtlSeconds()
        );
        TotpService totpService = new TotpService(storageManager.getTotpRepository());

        AuthService authService = new AuthService(
            storageManager.getUserRepository(),
            passwordHasher,
            bruteForce,
            sessionManager,
            messageService,
            pluginConfig.getSecurity().getPasswordPolicy()
        );

        registerCommands(authService, verificationService, passwordResetService, totpService);
        registerListeners(config);

        SchedulerUtil.runGlobalTimer(this, sessionManager::expireSessions, 20L * 60, 20L * 60);
        SchedulerUtil.runGlobalTimer(this, this::monitorPoolUsage, 20L * 60, 20L * 60);
        getLogger().info("MoontrixLogin enabled");
    }

    @Override
    public void onDisable() {
        if (ipReputationService != null) {
            ipReputationService.shutdown();
        }
        if (sessionManager != null) {
            sessionManager.flushRememberTokens();
        }
        if (storageManager != null) {
            storageManager.shutdown();
        }
        getLogger().info("MoontrixLogin disabled");
    }

    private void registerCommands(AuthService authService, VerificationService verificationService,
                                  PasswordResetService passwordResetService, TotpService totpService) {
        setExecutor("moontrixlogin", new RootCommand());
        setExecutor("login", new LoginCommand(this, authService, sessionManager, totpService, captchaService,
            antiBotService, messageService, deviceFingerprintService, jwtSessionTokenService,
            pluginConfig.getSecurity().getIpPrefixSegments(),
            pluginConfig.getSecurity().isRememberMeEnabled()));
        setExecutor("logout", new LogoutCommand(sessionManager, messageService));
        setExecutor("register", new RegisterCommand(this, authService, sessionManager,
            captchaService, antiBotService, messageService,
            pluginConfig.getRegistration().isEnabled(),
            pluginConfig.getRegistration().isRequireConfirmation(),
            deviceFingerprintService,
            pluginConfig.getSecurity().getIpPrefixSegments()));
        setExecutor("changepassword", new ChangePasswordCommand(this, authService, sessionManager));
        setExecutor("unregister", new UnregisterCommand(this, authService, sessionManager));

        EmailRateLimiter verifyLimiter = new EmailRateLimiter(
            pluginConfig.getMail().getVerifyMaxPerWindow(),
            pluginConfig.getMail().getVerifyWindowSeconds(),
            pluginConfig.getMail().getVerifyCooldownSeconds()
        );
        EmailRateLimiter resetLimiter = new EmailRateLimiter(
            pluginConfig.getMail().getResetMaxPerWindow(),
            pluginConfig.getMail().getResetWindowSeconds(),
            pluginConfig.getMail().getResetCooldownSeconds()
        );
        EmailRecoverLimiter recoverLimiter = new EmailRecoverLimiter(
            pluginConfig.getMail().getRecoverMaxPerWindow(),
            pluginConfig.getMail().getRecoverWindowSeconds(),
            pluginConfig.getMail().getRecoverCooldownSeconds()
        );
        setExecutor("email", new fr.lordmoontrix.moontrixlogin.command.EmailCommand(
            this, storageManager.getUserRepository(), verificationService, passwordResetService,
            messageService, sessionManager, emailService, passwordHasher,
            pluginConfig.getSecurity().getPasswordPolicy(),
            verifyLimiter, resetLimiter, recoverLimiter));
        setExecutor("totp", new fr.lordmoontrix.moontrixlogin.command.TotpCommand(
            this, totpService, messageService, sessionManager));
        setExecutor("captcha", new fr.lordmoontrix.moontrixlogin.command.CaptchaCommand(
            messageService, captchaService));
        setExecutor("verification", new fr.lordmoontrix.moontrixlogin.command.VerificationCommand(
            this, storageManager.getUserRepository(), verificationService, messageService, sessionManager));
    }

    private void registerListeners(PluginConfig config) {
        Bukkit.getPluginManager().registerEvents(
            new PlayerConnectionListener(this, storageManager.getUserRepository(), sessionManager, messageService,
                captchaService, config.getSecurity().isCaptchaEnabled(), antiBotService,
                config.getSecurity().isInvalidateOnIpChange(),
                config.getSecurity().getIpPrefixSegments(),
                config.getSecurity().getLoginTimeoutSeconds(),
                config.getSecurity().isKickOnTimeout(),
                deviceFingerprintService,
                jwtSessionTokenService,
                config.getSecurity().isRememberMeEnabled()),
            this
        );
        Bukkit.getPluginManager().registerEvents(
            new PlayerProtectionListener(sessionManager, config.getProtection(), messageService, captchaService,
                antiBotService),
            this
        );
    }

    private void setExecutor(String commandName, org.bukkit.command.CommandExecutor executor) {
        PluginCommand command = getCommand(commandName);
        if (command != null) {
            command.setExecutor(executor);
        }
    }

    private void saveIfMissing(String resourcePath) {
        if (!getDataFolder().toPath().resolve(resourcePath).toFile().exists()) {
            saveResource(resourcePath, false);
        }
    }

    private void monitorPoolUsage() {
        if (storageManager == null || storageManager.getDataSource() == null) {
            return;
        }
        var mxBean = storageManager.getDataSource().getHikariPoolMXBean();
        if (mxBean == null) {
            return;
        }
        int active = mxBean.getActiveConnections();
        int total = mxBean.getTotalConnections();
        int waiting = mxBean.getThreadsAwaitingConnection();
        if (total > 0 && active >= (int) Math.floor(total * 0.8)) {
            getLogger().warning("DB pool usage is high: active=" + active + "/" + total + ", waiting=" + waiting);
        }
    }
}
