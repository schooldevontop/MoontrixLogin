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
import fr.lordmoontrix.moontrixlogin.util.PlatformRuntimeCheck;
import fr.lordmoontrix.moontrixlogin.util.SchedulerUtil;
import fr.lordmoontrix.moontrixlogin.util.ServerVersionRuntimeCheck;
import java.nio.file.Path;
import java.time.Duration;
import org.bukkit.Bukkit;
import org.bukkit.command.PluginCommand;
import org.bukkit.event.HandlerList;
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
    private PlayerConnectionListener playerConnectionListener;
    private PlayerProtectionListener playerProtectionListener;

    @Override
    public void onEnable() {
        PlatformRuntimeCheck.logPlatform(getLogger());
        ServerVersionRuntimeCheck.logCompatibility(getLogger());

        if (!getDataFolder().exists() && !getDataFolder().mkdirs()) {
            getLogger().warning("Failed to create plugin data folder.");
        }
        saveDefaultConfig();
        if (!getDataFolder().toPath().resolve("messages/messages_en.yml").toFile().exists()) {
            saveResource("messages/messages_en.yml", false);
        }
        if (!getDataFolder().toPath().resolve("messages/messages_vi.yml").toFile().exists()) {
            saveResource("messages/messages_vi.yml", false);
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
        getLogger().info("[Messages] Active language: " + messageService.getLanguageCode());
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
        if (playerConnectionListener != null) {
            HandlerList.unregisterAll(playerConnectionListener);
        }
        if (playerProtectionListener != null) {
            HandlerList.unregisterAll(playerProtectionListener);
        }
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

    public synchronized String reloadRuntime() {
        PluginConfig newConfig;
        IpReputationService newIpReputationService = null;
        PluginConfig previousConfig = this.pluginConfig;
        try {
            getLogger().info("[Reload] Starting runtime hot-reload...");
            reloadConfig();
            newConfig = PluginConfig.from(getConfig());
            getLogger().info("[Reload] Config parsed successfully.");

            MessageService newMessageService = new MessageService(this);
            getLogger().info("[Reload] Message module reloaded (messages/messages_"
                + newMessageService.getLanguageCode() + ".yml).");
            CaptchaService newCaptchaService = new CaptchaService(
                newConfig.getSecurity().getCaptchaCodeLength(),
                newConfig.getSecurity().getCaptchaTtlSeconds()
            );
            getLogger().info("[Reload] Captcha module reloaded: enabled=" + newConfig.getSecurity().isCaptchaEnabled()
                + ", codeLength=" + newConfig.getSecurity().getCaptchaCodeLength()
                + ", ttlSeconds=" + newConfig.getSecurity().getCaptchaTtlSeconds());
            newIpReputationService = new IpReputationService(newConfig.getAntiBot());
            AntiBotService newAntiBotService = new AntiBotService(newConfig.getAntiBot(), newIpReputationService);
            getLogger().info("[Reload] AntiBot module reloaded: loginDelaySeconds="
                + newConfig.getAntiBot().getLoginDelaySeconds()
                + ", suspiciousDelaySeconds=" + newConfig.getAntiBot().getSuspiciousDelaySeconds()
                + ", shadowBanSeconds=" + newConfig.getAntiBot().getShadowBanSeconds()
                + ", abuseIpDbEnabled=" + newConfig.getAntiBot().isAbuseIpDbEnabled()
                + ", abuseIpDbMinConfidenceScore=" + newConfig.getAntiBot().getAbuseIpDbMinConfidenceScore());
            PasswordHasher newPasswordHasher = new BCryptHasher(newConfig.getSecurity().getBcryptCost());
            getLogger().info("[Reload] Security module reloaded: bcryptCost="
                + newConfig.getSecurity().getBcryptCost()
                + ", sessionTimeoutSeconds=" + newConfig.getSecurity().getSessionTimeoutSeconds()
                + ", bruteForceMaxAttempts=" + newConfig.getSecurity().getBruteForceMaxAttempts()
                + ", bruteForceWindowSeconds=" + newConfig.getSecurity().getBruteForceWindowSeconds());
            EmailService newEmailService = new EmailService(newConfig.getMail(), storageManager.getExecutor(), getLogger());
            getLogger().info("[Reload] Mail module reloaded: enabled=" + newConfig.getMail().isEnabled()
                + ", host=" + newConfig.getMail().getHost()
                + ", port=" + newConfig.getMail().getPort()
                + ", tls=" + newConfig.getMail().isUseTls()
                + ", ssl=" + newConfig.getMail().isUseSsl());
            JwtSessionTokenService newJwtSessionTokenService = null;

            if (newConfig.getSecurity().isRememberMeEnabled()) {
                newJwtSessionTokenService = new JwtSessionTokenService(
                    newConfig.getSecurity().getJwtSecret(),
                    newConfig.getSecurity().getJwtIssuer(),
                    newConfig.getSecurity().getRememberMeTtlDays()
                );
            }
            boolean previousRememberMe = previousConfig != null && previousConfig.getSecurity().isRememberMeEnabled();
            getLogger().info("[Reload] RememberMe module reloaded: enabled=" + newConfig.getSecurity().isRememberMeEnabled()
                + ", ttlDays=" + newConfig.getSecurity().getRememberMeTtlDays()
                + ", issuer=" + newConfig.getSecurity().getJwtIssuer()
                + ", stateChange=" + (previousRememberMe != newConfig.getSecurity().isRememberMeEnabled()
                ? (previousRememberMe ? "DISABLED" : "ENABLED") : "UNCHANGED"));

            sessionManager.reconfigure(
                Duration.ofSeconds(newConfig.getSecurity().getSessionTimeoutSeconds()),
                newConfig.getSecurity().getJwtSecret()
            );
            getLogger().info("[Reload] Session manager reconfigured.");

            BruteForceProtector bruteForce = new BruteForceProtector(
                newConfig.getSecurity().getBruteForceMaxAttempts(),
                newConfig.getSecurity().getBruteForceWindowSeconds(),
                newConfig.getSecurity().getBruteForceProgressiveLockSeconds()
            );
            VerificationService verificationService = new VerificationService(
                storageManager.getEmailVerificationRepository(),
                newConfig.getSecurity().getVerificationCodeLength(),
                newConfig.getSecurity().getVerificationCodeTtlSeconds()
            );
            PasswordResetService newPasswordResetService = new PasswordResetService(
                storageManager.getPasswordResetRepository(),
                newConfig.getSecurity().getVerificationCodeLength(),
                newConfig.getSecurity().getVerificationCodeTtlSeconds()
            );
            TotpService totpService = new TotpService(storageManager.getTotpRepository());
            AuthService authService = new AuthService(
                storageManager.getUserRepository(),
                newPasswordHasher,
                bruteForce,
                sessionManager,
                newMessageService,
                newConfig.getSecurity().getPasswordPolicy()
            );

            IpReputationService previousIpReputationService = this.ipReputationService;
            this.pluginConfig = newConfig;
            this.messageService = newMessageService;
            this.captchaService = newCaptchaService;
            this.ipReputationService = newIpReputationService;
            this.antiBotService = newAntiBotService;
            this.passwordHasher = newPasswordHasher;
            this.emailService = newEmailService;
            this.jwtSessionTokenService = newJwtSessionTokenService;
            this.passwordResetService = newPasswordResetService;

            registerCommands(authService, verificationService, newPasswordResetService, totpService);
            getLogger().info("[Reload] Command executors rebound.");
            registerListeners(newConfig);
            getLogger().info("[Reload] Event listeners rebound.");

            if (previousIpReputationService != null) {
                previousIpReputationService.shutdown();
                getLogger().info("[Reload] Previous IpReputationService shutdown completed.");
            }
            getLogger().info("[Reload] Runtime hot-reload completed successfully.");
            return null;
        } catch (Exception ex) {
            if (newIpReputationService != null) {
                newIpReputationService.shutdown();
            }
            getLogger().severe("Hot-reload failed: " + ex.getMessage());
            return ex.getMessage();
        }
    }

    private void registerCommands(AuthService authService, VerificationService verificationService,
                                  PasswordResetService passwordResetService, TotpService totpService) {
        setExecutor("moontrixlogin", new RootCommand(this, sessionManager, storageManager.getUserRepository(), messageService));
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
        if (playerConnectionListener != null) {
            HandlerList.unregisterAll(playerConnectionListener);
        }
        if (playerProtectionListener != null) {
            HandlerList.unregisterAll(playerProtectionListener);
        }

        playerConnectionListener = new PlayerConnectionListener(this, storageManager.getUserRepository(),
            sessionManager, messageService, captchaService, config.getSecurity().isCaptchaEnabled(), antiBotService,
            config.getSecurity().isInvalidateOnIpChange(), config.getSecurity().getIpPrefixSegments(),
            config.getSecurity().getLoginTimeoutSeconds(), config.getSecurity().isKickOnTimeout(),
            deviceFingerprintService, jwtSessionTokenService, config.getSecurity().isRememberMeEnabled());
        Bukkit.getPluginManager().registerEvents(
            playerConnectionListener,
            this
        );

        playerProtectionListener = new PlayerProtectionListener(this, sessionManager, config.getProtection(),
            messageService, captchaService, antiBotService);
        Bukkit.getPluginManager().registerEvents(
            playerProtectionListener,
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
        com.zaxxer.hikari.HikariPoolMXBean mxBean = storageManager.getDataSource().getHikariPoolMXBean();
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


