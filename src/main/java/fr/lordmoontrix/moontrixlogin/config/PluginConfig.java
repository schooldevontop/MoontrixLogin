package fr.lordmoontrix.moontrixlogin.config;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bukkit.configuration.file.FileConfiguration;

public final class PluginConfig {
    private final Storage storage;
    private final Security security;
    private final Protection protection;
    private final Mail mail;
    private final AntiBot antiBot;

    public PluginConfig(Storage storage, Security security, Protection protection, Mail mail, AntiBot antiBot) {
        this.storage = storage;
        this.security = security;
        this.protection = protection;
        this.mail = mail;
        this.antiBot = antiBot;
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

    public static PluginConfig from(FileConfiguration config) {
        Storage storage = new Storage(
            config.getString("storage.type", "SQLITE"),
            config.getString("storage.mysql.host", "localhost"),
            config.getInt("storage.mysql.port", 3306),
            config.getString("storage.mysql.database", "moontrixlogin"),
            config.getString("storage.mysql.username", "root"),
            config.getString("storage.mysql.password", "password"),
            config.getInt("storage.mysql.poolSize", 10),
            config.getString("storage.sqlite.file", "moontrixlogin.db")
        );

        Security security = new Security(
            config.getInt("security.bcrypt.cost", 12),
            config.getInt("security.sessionTimeoutSeconds", 600),
            config.getInt("security.bruteForce.maxAttempts", 5),
            config.getInt("security.bruteForce.windowSeconds", 300),
            config.getInt("security.bruteForce.lockSeconds", 600),
            config.getInt("security.verification.codeLength", 6),
            config.getInt("security.verification.codeTtlSeconds", 600),
            config.getBoolean("security.captcha.enabled", false),
            config.getInt("security.captcha.codeLength", 4),
            config.getInt("security.captcha.ttlSeconds", 180)
        );

        List<String> allowed = config.getStringList("protection.allowedCommands");
        Protection protection = new Protection(
            config.getBoolean("protection.blockChatBeforeLogin", true),
            config.getBoolean("protection.blockCommandsBeforeLogin", true),
            config.getBoolean("protection.blockMovementBeforeLogin", true),
            new HashSet<>(allowed)
        );

        Mail mail = new Mail(
            config.getBoolean("mail.enabled", false),
            config.getString("mail.host", "smtp.example.com"),
            config.getInt("mail.port", 587),
            config.getString("mail.username", ""),
            config.getString("mail.password", ""),
            config.getString("mail.from", "MoontrixLogin <noreply@example.com>"),
            config.getBoolean("mail.useTls", true),
            config.getBoolean("mail.useSsl", false),
            config.getInt("mail.verify.maxPerWindow", 5),
            config.getInt("mail.verify.windowSeconds", 900),
            config.getInt("mail.verify.cooldownSeconds", 60),
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
            config.getInt("antiBot.distinctNamesWindowSeconds", 60)
        );

        return new PluginConfig(storage, security, protection, mail, antiBot);
    }

    public static final class Storage {
        private final String type;
        private final String mysqlHost;
        private final int mysqlPort;
        private final String mysqlDatabase;
        private final String mysqlUsername;
        private final String mysqlPassword;
        private final int mysqlPoolSize;
        private final String sqliteFile;

        public Storage(String type, String mysqlHost, int mysqlPort, String mysqlDatabase,
                       String mysqlUsername, String mysqlPassword, int mysqlPoolSize, String sqliteFile) {
            this.type = type;
            this.mysqlHost = mysqlHost;
            this.mysqlPort = mysqlPort;
            this.mysqlDatabase = mysqlDatabase;
            this.mysqlUsername = mysqlUsername;
            this.mysqlPassword = mysqlPassword;
            this.mysqlPoolSize = mysqlPoolSize;
            this.sqliteFile = sqliteFile;
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

        public String getSqliteFile() {
            return sqliteFile;
        }
    }

    public static final class Security {
        private final int bcryptCost;
        private final int sessionTimeoutSeconds;
        private final int bruteForceMaxAttempts;
        private final int bruteForceWindowSeconds;
        private final int bruteForceLockSeconds;
        private final int verificationCodeLength;
        private final int verificationCodeTtlSeconds;
        private final boolean captchaEnabled;
        private final int captchaCodeLength;
        private final int captchaTtlSeconds;

        public Security(int bcryptCost, int sessionTimeoutSeconds, int bruteForceMaxAttempts,
                        int bruteForceWindowSeconds, int bruteForceLockSeconds,
                        int verificationCodeLength, int verificationCodeTtlSeconds,
                        boolean captchaEnabled, int captchaCodeLength, int captchaTtlSeconds) {
            this.bcryptCost = bcryptCost;
            this.sessionTimeoutSeconds = sessionTimeoutSeconds;
            this.bruteForceMaxAttempts = bruteForceMaxAttempts;
            this.bruteForceWindowSeconds = bruteForceWindowSeconds;
            this.bruteForceLockSeconds = bruteForceLockSeconds;
            this.verificationCodeLength = verificationCodeLength;
            this.verificationCodeTtlSeconds = verificationCodeTtlSeconds;
            this.captchaEnabled = captchaEnabled;
            this.captchaCodeLength = captchaCodeLength;
            this.captchaTtlSeconds = captchaTtlSeconds;
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
        private final int recoverMaxPerWindow;
        private final int recoverWindowSeconds;
        private final int recoverCooldownSeconds;

        public Mail(boolean enabled, String host, int port, String username, String password,
                    String from, boolean useTls, boolean useSsl,
                    int verifyMaxPerWindow, int verifyWindowSeconds, int verifyCooldownSeconds,
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

        public AntiBot(int loginDelaySeconds, int suspiciousDelaySeconds, int shadowBanSeconds,
                       int bruteForceLockSeconds, int maxLoginPerIpWindow, int loginWindowSeconds,
                       int maxNewPlayersPerIpWindow, int newPlayerWindowSeconds,
                       int maxDistinctNamesPerIpWindow, int distinctNamesWindowSeconds) {
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
    }
}
