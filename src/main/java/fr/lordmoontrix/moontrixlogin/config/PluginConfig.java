package fr.lordmoontrix.moontrixlogin.config;

import fr.lordmoontrix.moontrixlogin.security.PasswordPolicy;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bukkit.configuration.file.FileConfiguration;

public final class PluginConfig {
    private static final String DEFAULT_DB_PASSWORD_ENV = "MOONTRIX_DB_PASSWORD";
    private static final String DEFAULT_SMTP_PASSWORD_ENV = "MOONTRIX_SMTP_PASSWORD";

    private final Storage storage;
    private final Security security;
    private final Protection protection;
    private final Mail mail;
    private final AntiBot antiBot;
    private final Registration registration;

    public PluginConfig(Storage storage, Security security, Protection protection,
                        Mail mail, AntiBot antiBot, Registration registration) {
        this.storage = storage;
        this.security = security;
        this.protection = protection;
        this.mail = mail;
        this.antiBot = antiBot;
        this.registration = registration;
    }

    public Storage getStorage() {
        return storage;
    }

    public Security getSecurity() {
        return security;
    }

    public Protection getProtection() {
        return protection;
    }

    public Mail getMail() {
        return mail;
    }

    public AntiBot getAntiBot() {
        return antiBot;
    }

    public Registration getRegistration() {
        return registration;
    }

    public static PluginConfig from(FileConfiguration config) {
        SecretResolver secretResolver = new SecretResolver();
        boolean mysqlEnabled = "MYSQL".equalsIgnoreCase(config.getString("storage.type", "SQLITE"));
        boolean mailEnabled = config.getBoolean("mail.enabled", false);

        String mysqlPassword = mysqlEnabled
            ? secretResolver.resolve(
                config.getString("storage.mysql.password", ""),
                config.getString("storage.mysql.passwordEnv", DEFAULT_DB_PASSWORD_ENV)
            )
            : config.getString("storage.mysql.password", "");
        String mailPassword = mailEnabled
            ? secretResolver.resolve(
                config.getString("mail.password", ""),
                config.getString("mail.passwordEnv", DEFAULT_SMTP_PASSWORD_ENV)
            )
            : config.getString("mail.password", "");

        Storage.Cache cache = new Storage.Cache(
            config.getBoolean("storage.cache.enabled", true),
            config.getInt("storage.cache.ttlSeconds", 60),
            config.getInt("storage.cache.maxEntries", 10_000)
        );

        Storage storage = new Storage(
            config.getString("storage.type", "SQLITE"),
            config.getString("storage.mysql.host", "localhost"),
            config.getInt("storage.mysql.port", 3306),
            config.getString("storage.mysql.database", "moontrixlogin"),
            config.getString("storage.mysql.username", "root"),
            mysqlPassword,
            config.getInt("storage.mysql.poolSize", 16),
            config.getInt("storage.mysql.minimumIdle", 4),
            config.getLong("storage.mysql.connectionTimeoutMs", 15_000L),
            config.getLong("storage.mysql.idleTimeoutMs", 300_000L),
            config.getLong("storage.mysql.maxLifetimeMs", 1_800_000L),
            config.getLong("storage.mysql.leakDetectionThresholdMs", 0L),
            config.getString("storage.sqlite.file", "moontrixlogin.db"),
            cache
        );

        List<String> blacklist = config.getStringList("security.passwordPolicy.blacklist");
        PasswordPolicy policy = new PasswordPolicy(
            config.getInt("security.passwordPolicy.minLength", 6),
            config.getInt("security.passwordPolicy.maxLength", 64),
            config.getBoolean("security.passwordPolicy.requireUppercase", false),
            config.getBoolean("security.passwordPolicy.requireLowercase", true),
            config.getBoolean("security.passwordPolicy.requireNumber", true),
            config.getBoolean("security.passwordPolicy.requireSymbol", false),
            blacklist
        );

        int bruteForceLockSeconds = config.getInt("security.bruteForce.lockSeconds", 600);
        int[] progressiveLocks = toIntArray(
            config.getIntegerList("security.bruteForce.progressiveLockSeconds"),
            bruteForceLockSeconds
        );

        Security security = new Security(
            config.getInt("security.bcrypt.cost", 12),
            config.getInt("security.sessionTimeoutSeconds", 600),
            config.getInt("security.bruteForce.maxAttempts", 5),
            config.getInt("security.bruteForce.windowSeconds", 300),
            bruteForceLockSeconds,
            progressiveLocks,
            config.getInt("security.verification.codeLength", 6),
            config.getInt("security.verification.codeTtlSeconds", 600),
            config.getBoolean("security.captcha.enabled", false),
            config.getInt("security.captcha.codeLength", 4),
            config.getInt("security.captcha.ttlSeconds", 180),
            config.getInt("security.login.timeoutSeconds", 60),
            config.getBoolean("security.login.kickOnTimeout", true),
            config.getBoolean("security.session.invalidateOnIpChange", true),
            config.getInt("security.session.ipPrefixSegments", 4),
            config.getBoolean("security.session.rememberMe.enabled", false),
            config.getInt("security.session.rememberMe.ttlDays", 30),
            config.getString("security.session.jwt.issuer", "MoontrixLogin"),
            secretResolver.resolve(
                config.getString("security.session.jwt.secret", ""),
                config.getString("security.session.jwt.secretEnv", "MOONTRIX_JWT_SECRET")
            ),
            policy
        );

        List<String> allowed = config.getStringList("protection.allowedCommands");
        Protection protection = new Protection(
            config.getBoolean("protection.blockChatBeforeLogin", true),
            config.getBoolean("protection.blockCommandsBeforeLogin", true),
            config.getBoolean("protection.blockMovementBeforeLogin", true),
            new HashSet<>(allowed)
        );

        Mail mail = new Mail(
            mailEnabled,
            config.getString("mail.host", "smtp.example.com"),
            config.getInt("mail.port", 587),
            config.getString("mail.username", ""),
            mailPassword,
            config.getString("mail.from", "MoontrixLogin <noreply@example.com>"),
            config.getBoolean("mail.useTls", true),
            config.getBoolean("mail.useSsl", false),
            config.getInt("mail.verify.maxPerWindow", 5),
            config.getInt("mail.verify.windowSeconds", 900),
            config.getInt("mail.verify.cooldownSeconds", 60),
            config.getInt("mail.reset.maxPerWindow", 5),
            config.getInt("mail.reset.windowSeconds", 300),
            config.getInt("mail.reset.cooldownSeconds", 300),
            config.getInt("mail.recover.maxPerWindow", 3),
            config.getInt("mail.recover.windowSeconds", 900),
            config.getInt("mail.recover.cooldownSeconds", 60)
        );

        AntiBot antiBot = new AntiBot(
            config.getInt("antiBot.loginDelaySeconds", 2),
            config.getInt("antiBot.suspiciousDelaySeconds", 5),
            config.getInt("antiBot.shadowBanSeconds", 120),
            config.getInt("antiBot.bruteForceLockSeconds", 600),
            config.getInt("antiBot.maxLoginPerIpWindow", 5),
            config.getInt("antiBot.loginWindowSeconds", 10),
            config.getInt("antiBot.maxNewPlayersPerIpWindow", 3),
            config.getInt("antiBot.newPlayerWindowSeconds", 60),
            config.getInt("antiBot.maxDistinctNamesPerIpWindow", 5),
            config.getInt("antiBot.distinctNamesWindowSeconds", 60),
            config.getBoolean("antiBot.adaptiveCaptcha.enabled", true),
            config.getInt("antiBot.deviceFingerprint.banThreshold", 20),
            config.getBoolean("antiBot.abuseIpDb.enabled", false),
            secretResolver.resolve(
                config.getString("antiBot.abuseIpDb.apiKey", ""),
                config.getString("antiBot.abuseIpDb.apiKeyEnv", "MOONTRIX_ABUSEIPDB_API_KEY")
            ),
            config.getInt("antiBot.abuseIpDb.minConfidenceScore", 85),
            config.getInt("antiBot.abuseIpDb.cacheSeconds", 3600),
            config.getInt("antiBot.abuseIpDb.failureBackoffSeconds", 120),
            config.getInt("antiBot.abuseIpDb.requestTimeoutMs", 4000),
            config.getInt("antiBot.abuseIpDb.maxAgeDays", 30)
        );

        Registration registration = new Registration(
            config.getBoolean("registration.enabled", true),
            config.getBoolean("registration.requireConfirmation", true)
        );

        return new PluginConfig(storage, security, protection, mail, antiBot, registration);
    }

    private static int[] toIntArray(List<Integer> values, int fallback) {
        if (values == null || values.isEmpty()) {
            return new int[] {fallback};
        }
        return values.stream().mapToInt(v -> Math.max(1, v)).toArray();
    }

    public static final class Storage {
        private final String type;
        private final String mysqlHost;
        private final int mysqlPort;
        private final String mysqlDatabase;
        private final String mysqlUsername;
        private final String mysqlPassword;
        private final int mysqlPoolSize;
        private final int mysqlMinimumIdle;
        private final long mysqlConnectionTimeoutMs;
        private final long mysqlIdleTimeoutMs;
        private final long mysqlMaxLifetimeMs;
        private final long mysqlLeakDetectionThresholdMs;
        private final String sqliteFile;
        private final Cache cache;

        public Storage(String type, String mysqlHost, int mysqlPort, String mysqlDatabase,
                       String mysqlUsername, String mysqlPassword, int mysqlPoolSize,
                       int mysqlMinimumIdle, long mysqlConnectionTimeoutMs, long mysqlIdleTimeoutMs,
                       long mysqlMaxLifetimeMs, long mysqlLeakDetectionThresholdMs,
                       String sqliteFile, Cache cache) {
            this.type = type;
            this.mysqlHost = mysqlHost;
            this.mysqlPort = mysqlPort;
            this.mysqlDatabase = mysqlDatabase;
            this.mysqlUsername = mysqlUsername;
            this.mysqlPassword = mysqlPassword;
            this.mysqlPoolSize = mysqlPoolSize;
            this.mysqlMinimumIdle = mysqlMinimumIdle;
            this.mysqlConnectionTimeoutMs = mysqlConnectionTimeoutMs;
            this.mysqlIdleTimeoutMs = mysqlIdleTimeoutMs;
            this.mysqlMaxLifetimeMs = mysqlMaxLifetimeMs;
            this.mysqlLeakDetectionThresholdMs = mysqlLeakDetectionThresholdMs;
            this.sqliteFile = sqliteFile;
            this.cache = cache;
        }

        public String getType() {
            return type;
        }

        public String getMysqlHost() {
            return mysqlHost;
        }

        public int getMysqlPort() {
            return mysqlPort;
        }

        public String getMysqlDatabase() {
            return mysqlDatabase;
        }

        public String getMysqlUsername() {
            return mysqlUsername;
        }

        public String getMysqlPassword() {
            return mysqlPassword;
        }

        public int getMysqlPoolSize() {
            return mysqlPoolSize;
        }

        public int getMysqlMinimumIdle() {
            return mysqlMinimumIdle;
        }

        public long getMysqlConnectionTimeoutMs() {
            return mysqlConnectionTimeoutMs;
        }

        public long getMysqlIdleTimeoutMs() {
            return mysqlIdleTimeoutMs;
        }

        public long getMysqlMaxLifetimeMs() {
            return mysqlMaxLifetimeMs;
        }

        public long getMysqlLeakDetectionThresholdMs() {
            return mysqlLeakDetectionThresholdMs;
        }

        public String getSqliteFile() {
            return sqliteFile;
        }

        public Cache getCache() {
            return cache;
        }

        public static final class Cache {
            private final boolean enabled;
            private final int ttlSeconds;
            private final int maxEntries;

            public Cache(boolean enabled, int ttlSeconds, int maxEntries) {
                this.enabled = enabled;
                this.ttlSeconds = ttlSeconds;
                this.maxEntries = maxEntries;
            }

            public boolean isEnabled() {
                return enabled;
            }

            public int getTtlSeconds() {
                return ttlSeconds;
            }

            public int getMaxEntries() {
                return maxEntries;
            }
        }
    }

    public static final class Security {
        private final int bcryptCost;
        private final int sessionTimeoutSeconds;
        private final int bruteForceMaxAttempts;
        private final int bruteForceWindowSeconds;
        private final int bruteForceLockSeconds;
        private final int[] bruteForceProgressiveLockSeconds;
        private final int verificationCodeLength;
        private final int verificationCodeTtlSeconds;
        private final boolean captchaEnabled;
        private final int captchaCodeLength;
        private final int captchaTtlSeconds;
        private final int loginTimeoutSeconds;
        private final boolean kickOnTimeout;
        private final boolean invalidateOnIpChange;
        private final int ipPrefixSegments;
        private final boolean rememberMeEnabled;
        private final int rememberMeTtlDays;
        private final String jwtIssuer;
        private final String jwtSecret;
        private final PasswordPolicy passwordPolicy;

        public Security(int bcryptCost, int sessionTimeoutSeconds, int bruteForceMaxAttempts,
                        int bruteForceWindowSeconds, int bruteForceLockSeconds,
                        int[] bruteForceProgressiveLockSeconds,
                        int verificationCodeLength, int verificationCodeTtlSeconds,
                        boolean captchaEnabled, int captchaCodeLength, int captchaTtlSeconds,
                        int loginTimeoutSeconds, boolean kickOnTimeout, boolean invalidateOnIpChange,
                        int ipPrefixSegments, boolean rememberMeEnabled, int rememberMeTtlDays,
                        String jwtIssuer, String jwtSecret, PasswordPolicy passwordPolicy) {
            this.bcryptCost = bcryptCost;
            this.sessionTimeoutSeconds = sessionTimeoutSeconds;
            this.bruteForceMaxAttempts = bruteForceMaxAttempts;
            this.bruteForceWindowSeconds = bruteForceWindowSeconds;
            this.bruteForceLockSeconds = bruteForceLockSeconds;
            this.bruteForceProgressiveLockSeconds = bruteForceProgressiveLockSeconds;
            this.verificationCodeLength = verificationCodeLength;
            this.verificationCodeTtlSeconds = verificationCodeTtlSeconds;
            this.captchaEnabled = captchaEnabled;
            this.captchaCodeLength = captchaCodeLength;
            this.captchaTtlSeconds = captchaTtlSeconds;
            this.loginTimeoutSeconds = loginTimeoutSeconds;
            this.kickOnTimeout = kickOnTimeout;
            this.invalidateOnIpChange = invalidateOnIpChange;
            this.ipPrefixSegments = ipPrefixSegments;
            this.rememberMeEnabled = rememberMeEnabled;
            this.rememberMeTtlDays = rememberMeTtlDays;
            this.jwtIssuer = jwtIssuer;
            this.jwtSecret = jwtSecret;
            this.passwordPolicy = passwordPolicy;
        }

        public int getBcryptCost() {
            return bcryptCost;
        }

        public int getSessionTimeoutSeconds() {
            return sessionTimeoutSeconds;
        }

        public int getBruteForceMaxAttempts() {
            return bruteForceMaxAttempts;
        }

        public int getBruteForceWindowSeconds() {
            return bruteForceWindowSeconds;
        }

        public int getBruteForceLockSeconds() {
            return bruteForceLockSeconds;
        }

        public int[] getBruteForceProgressiveLockSeconds() {
            return bruteForceProgressiveLockSeconds;
        }

        public int getVerificationCodeLength() {
            return verificationCodeLength;
        }

        public int getVerificationCodeTtlSeconds() {
            return verificationCodeTtlSeconds;
        }

        public boolean isCaptchaEnabled() {
            return captchaEnabled;
        }

        public int getCaptchaCodeLength() {
            return captchaCodeLength;
        }

        public int getCaptchaTtlSeconds() {
            return captchaTtlSeconds;
        }

        public int getLoginTimeoutSeconds() {
            return loginTimeoutSeconds;
        }

        public boolean isKickOnTimeout() {
            return kickOnTimeout;
        }

        public boolean isInvalidateOnIpChange() {
            return invalidateOnIpChange;
        }

        public int getIpPrefixSegments() {
            return ipPrefixSegments;
        }

        public boolean isRememberMeEnabled() {
            return rememberMeEnabled;
        }

        public int getRememberMeTtlDays() {
            return rememberMeTtlDays;
        }

        public String getJwtIssuer() {
            return jwtIssuer;
        }

        public String getJwtSecret() {
            return jwtSecret;
        }

        public PasswordPolicy getPasswordPolicy() {
            return passwordPolicy;
        }
    }

    public static final class Protection {
        private final boolean blockChatBeforeLogin;
        private final boolean blockCommandsBeforeLogin;
        private final boolean blockMovementBeforeLogin;
        private final Set<String> allowedCommands;

        public Protection(boolean blockChatBeforeLogin, boolean blockCommandsBeforeLogin,
                          boolean blockMovementBeforeLogin, Set<String> allowedCommands) {
            this.blockChatBeforeLogin = blockChatBeforeLogin;
            this.blockCommandsBeforeLogin = blockCommandsBeforeLogin;
            this.blockMovementBeforeLogin = blockMovementBeforeLogin;
            this.allowedCommands = allowedCommands;
        }

        public boolean isBlockChatBeforeLogin() {
            return blockChatBeforeLogin;
        }

        public boolean isBlockCommandsBeforeLogin() {
            return blockCommandsBeforeLogin;
        }

        public boolean isBlockMovementBeforeLogin() {
            return blockMovementBeforeLogin;
        }

        public Set<String> getAllowedCommands() {
            return allowedCommands;
        }
    }

    public static final class Mail {
        private final boolean enabled;
        private final String host;
        private final int port;
        private final String username;
        private final String password;
        private final String from;
        private final boolean useTls;
        private final boolean useSsl;
        private final int verifyMaxPerWindow;
        private final int verifyWindowSeconds;
        private final int verifyCooldownSeconds;
        private final int resetMaxPerWindow;
        private final int resetWindowSeconds;
        private final int resetCooldownSeconds;
        private final int recoverMaxPerWindow;
        private final int recoverWindowSeconds;
        private final int recoverCooldownSeconds;

        public Mail(boolean enabled, String host, int port, String username, String password,
                    String from, boolean useTls, boolean useSsl,
                    int verifyMaxPerWindow, int verifyWindowSeconds, int verifyCooldownSeconds,
                    int resetMaxPerWindow, int resetWindowSeconds, int resetCooldownSeconds,
                    int recoverMaxPerWindow, int recoverWindowSeconds, int recoverCooldownSeconds) {
            this.enabled = enabled;
            this.host = host;
            this.port = port;
            this.username = username;
            this.password = password;
            this.from = from;
            this.useTls = useTls;
            this.useSsl = useSsl;
            this.verifyMaxPerWindow = verifyMaxPerWindow;
            this.verifyWindowSeconds = verifyWindowSeconds;
            this.verifyCooldownSeconds = verifyCooldownSeconds;
            this.resetMaxPerWindow = resetMaxPerWindow;
            this.resetWindowSeconds = resetWindowSeconds;
            this.resetCooldownSeconds = resetCooldownSeconds;
            this.recoverMaxPerWindow = recoverMaxPerWindow;
            this.recoverWindowSeconds = recoverWindowSeconds;
            this.recoverCooldownSeconds = recoverCooldownSeconds;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public String getHost() {
            return host;
        }

        public int getPort() {
            return port;
        }

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }

        public String getFrom() {
            return from;
        }

        public boolean isUseTls() {
            return useTls;
        }

        public boolean isUseSsl() {
            return useSsl;
        }

        public int getVerifyMaxPerWindow() {
            return verifyMaxPerWindow;
        }

        public int getVerifyWindowSeconds() {
            return verifyWindowSeconds;
        }

        public int getVerifyCooldownSeconds() {
            return verifyCooldownSeconds;
        }

        public int getResetMaxPerWindow() {
            return resetMaxPerWindow;
        }

        public int getResetWindowSeconds() {
            return resetWindowSeconds;
        }

        public int getResetCooldownSeconds() {
            return resetCooldownSeconds;
        }

        public int getRecoverMaxPerWindow() {
            return recoverMaxPerWindow;
        }

        public int getRecoverWindowSeconds() {
            return recoverWindowSeconds;
        }

        public int getRecoverCooldownSeconds() {
            return recoverCooldownSeconds;
        }
    }

    public static final class AntiBot {
        private final int loginDelaySeconds;
        private final int suspiciousDelaySeconds;
        private final int shadowBanSeconds;
        private final int bruteForceLockSeconds;
        private final int maxLoginPerIpWindow;
        private final int loginWindowSeconds;
        private final int maxNewPlayersPerIpWindow;
        private final int newPlayerWindowSeconds;
        private final int maxDistinctNamesPerIpWindow;
        private final int distinctNamesWindowSeconds;
        private final boolean adaptiveCaptchaEnabled;
        private final int fingerprintBanThreshold;
        private final boolean abuseIpDbEnabled;
        private final String abuseIpDbApiKey;
        private final int abuseIpDbMinConfidenceScore;
        private final int abuseIpDbCacheSeconds;
        private final int abuseIpDbFailureBackoffSeconds;
        private final int abuseIpDbRequestTimeoutMs;
        private final int abuseIpDbMaxAgeDays;

        public AntiBot(int loginDelaySeconds, int suspiciousDelaySeconds, int shadowBanSeconds,
                       int bruteForceLockSeconds, int maxLoginPerIpWindow, int loginWindowSeconds,
                       int maxNewPlayersPerIpWindow, int newPlayerWindowSeconds,
                       int maxDistinctNamesPerIpWindow, int distinctNamesWindowSeconds,
                       boolean adaptiveCaptchaEnabled, int fingerprintBanThreshold,
                       boolean abuseIpDbEnabled, String abuseIpDbApiKey,
                       int abuseIpDbMinConfidenceScore, int abuseIpDbCacheSeconds,
                       int abuseIpDbFailureBackoffSeconds, int abuseIpDbRequestTimeoutMs,
                       int abuseIpDbMaxAgeDays) {
            this.loginDelaySeconds = loginDelaySeconds;
            this.suspiciousDelaySeconds = suspiciousDelaySeconds;
            this.shadowBanSeconds = shadowBanSeconds;
            this.bruteForceLockSeconds = bruteForceLockSeconds;
            this.maxLoginPerIpWindow = maxLoginPerIpWindow;
            this.loginWindowSeconds = loginWindowSeconds;
            this.maxNewPlayersPerIpWindow = maxNewPlayersPerIpWindow;
            this.newPlayerWindowSeconds = newPlayerWindowSeconds;
            this.maxDistinctNamesPerIpWindow = maxDistinctNamesPerIpWindow;
            this.distinctNamesWindowSeconds = distinctNamesWindowSeconds;
            this.adaptiveCaptchaEnabled = adaptiveCaptchaEnabled;
            this.fingerprintBanThreshold = fingerprintBanThreshold;
            this.abuseIpDbEnabled = abuseIpDbEnabled;
            this.abuseIpDbApiKey = abuseIpDbApiKey;
            this.abuseIpDbMinConfidenceScore = abuseIpDbMinConfidenceScore;
            this.abuseIpDbCacheSeconds = abuseIpDbCacheSeconds;
            this.abuseIpDbFailureBackoffSeconds = abuseIpDbFailureBackoffSeconds;
            this.abuseIpDbRequestTimeoutMs = abuseIpDbRequestTimeoutMs;
            this.abuseIpDbMaxAgeDays = abuseIpDbMaxAgeDays;
        }

        public int getLoginDelaySeconds() {
            return loginDelaySeconds;
        }

        public int getSuspiciousDelaySeconds() {
            return suspiciousDelaySeconds;
        }

        public int getShadowBanSeconds() {
            return shadowBanSeconds;
        }

        public int getBruteForceLockSeconds() {
            return bruteForceLockSeconds;
        }

        public int getMaxLoginPerIpWindow() {
            return maxLoginPerIpWindow;
        }

        public int getLoginWindowSeconds() {
            return loginWindowSeconds;
        }

        public int getMaxNewPlayersPerIpWindow() {
            return maxNewPlayersPerIpWindow;
        }

        public int getNewPlayerWindowSeconds() {
            return newPlayerWindowSeconds;
        }

        public int getMaxDistinctNamesPerIpWindow() {
            return maxDistinctNamesPerIpWindow;
        }

        public int getDistinctNamesWindowSeconds() {
            return distinctNamesWindowSeconds;
        }

        public boolean isAdaptiveCaptchaEnabled() {
            return adaptiveCaptchaEnabled;
        }

        public int getFingerprintBanThreshold() {
            return fingerprintBanThreshold;
        }

        public boolean isAbuseIpDbEnabled() {
            return abuseIpDbEnabled;
        }

        public String getAbuseIpDbApiKey() {
            return abuseIpDbApiKey;
        }

        public int getAbuseIpDbMinConfidenceScore() {
            return abuseIpDbMinConfidenceScore;
        }

        public int getAbuseIpDbCacheSeconds() {
            return abuseIpDbCacheSeconds;
        }

        public int getAbuseIpDbFailureBackoffSeconds() {
            return abuseIpDbFailureBackoffSeconds;
        }

        public int getAbuseIpDbRequestTimeoutMs() {
            return abuseIpDbRequestTimeoutMs;
        }

        public int getAbuseIpDbMaxAgeDays() {
            return abuseIpDbMaxAgeDays;
        }
    }

    public static final class Registration {
        private final boolean enabled;
        private final boolean requireConfirmation;

        public Registration(boolean enabled, boolean requireConfirmation) {
            this.enabled = enabled;
            this.requireConfirmation = requireConfirmation;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public boolean isRequireConfirmation() {
            return requireConfirmation;
        }
    }
}


