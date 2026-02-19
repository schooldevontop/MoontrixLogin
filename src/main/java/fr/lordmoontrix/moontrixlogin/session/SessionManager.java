package fr.lordmoontrix.moontrixlogin.session;

import fr.lordmoontrix.moontrixlogin.model.AuthState;
import fr.lordmoontrix.moontrixlogin.model.Session;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class SessionManager {
    private static final String ENCRYPTED_HEADER = "MLTOK2\n";
    private final Map<UUID, Session> sessions = new ConcurrentHashMap<>();
    private final Map<UUID, String> rememberTokens = new ConcurrentHashMap<>();
    private Duration timeout;
    private final Path rememberTokenFile;
    private SecretKey rememberTokenKey;
    private final Logger logger;

    public SessionManager(Duration timeout, Path dataFolder, String rememberStoreSecret, Logger logger) {
        this.timeout = timeout;
        this.rememberTokenFile = dataFolder.resolve("remember-tokens.properties");
        this.rememberTokenKey = deriveAesKey(rememberStoreSecret);
        this.logger = logger;
        loadRememberTokens();
    }

    public Session getOrCreate(UUID uuid, AuthState initial) {
        return sessions.computeIfAbsent(uuid, id -> new Session(id, initial));
    }

    public Optional<Session> get(UUID uuid) {
        return Optional.ofNullable(sessions.get(uuid));
    }

    public void remove(UUID uuid) {
        sessions.remove(uuid);
    }

    public void markAuthenticated(UUID uuid) {
        Session session = getOrCreate(uuid, AuthState.AUTHENTICATED);
        session.markAuthenticated();
    }

    public void markAuthenticated(UUID uuid, String ip) {
        Session session = getOrCreate(uuid, AuthState.AUTHENTICATED);
        session.setLastIp(ip);
        session.markAuthenticated();
    }

    public void markAuthenticated(UUID uuid, String ip, String fingerprint) {
        Session session = getOrCreate(uuid, AuthState.AUTHENTICATED);
        session.setLastIp(ip);
        session.setLastFingerprint(fingerprint);
        session.markAuthenticated();
    }

    public boolean isIpChanged(UUID uuid, String currentIp) {
        return isIpChanged(uuid, currentIp, 4);
    }

    public boolean isIpChanged(UUID uuid, String currentIp, int prefixSegments) {
        return get(uuid).map(s -> {
            String lastIp = s.getLastIp();
            if (lastIp == null || currentIp == null) {
                return false;
            }
            return !ipMatches(lastIp, currentIp, prefixSegments);
        }).orElse(false);
    }

    public boolean isContextChanged(UUID uuid, String currentIp, String fingerprint, int prefixSegments) {
        return get(uuid).map(s -> {
            boolean ipChanged = isIpChanged(uuid, currentIp, prefixSegments);
            String previousFingerprint = s.getLastFingerprint();
            boolean fingerprintChanged = previousFingerprint != null
                && fingerprint != null
                && !previousFingerprint.equals(fingerprint);
            return ipChanged || fingerprintChanged;
        }).orElse(false);
    }

    public void setRememberToken(UUID uuid, String token) {
        if (token == null || token.trim().isEmpty()) {
            rememberTokens.remove(uuid);
            saveRememberTokens();
            return;
        }
        rememberTokens.put(uuid, token);
        saveRememberTokens();
    }

    public Optional<String> getRememberToken(UUID uuid) {
        return Optional.ofNullable(rememberTokens.get(uuid));
    }

    public void clearRememberToken(UUID uuid) {
        rememberTokens.remove(uuid);
        saveRememberTokens();
    }

    public void flushRememberTokens() {
        saveRememberTokens();
    }

    public synchronized void reconfigure(Duration newTimeout, String rememberStoreSecret) {
        this.timeout = newTimeout;
        this.rememberTokenKey = deriveAesKey(rememberStoreSecret);
        saveRememberTokens();
    }

    private boolean ipMatches(String lastIp, String currentIp, int prefixSegments) {
        int segments = Math.max(1, Math.min(4, prefixSegments));
        String[] left = lastIp.split("\\.");
        String[] right = currentIp.split("\\.");
        if (left.length != 4 || right.length != 4) {
            return lastIp.equals(currentIp);
        }
        for (int i = 0; i < segments; i++) {
            if (!left[i].equals(right[i])) {
                return false;
            }
        }
        return true;
    }

    public void setState(UUID uuid, AuthState state) {
        Session session = getOrCreate(uuid, state);
        session.setState(state);
    }

    public void expireSessions() {
        Instant now = Instant.now();
        for (Session session : sessions.values()) {
            if (session.getState() == AuthState.AUTHENTICATED && session.getLastAuthenticatedAt() != null) {
                if (session.getLastAuthenticatedAt().plus(timeout).isBefore(now)) {
                    session.setState(AuthState.UNAUTHENTICATED);
                }
            }
        }
    }

    private synchronized void loadRememberTokens() {
        if (!Files.exists(rememberTokenFile)) {
            return;
        }
        try {
            byte[] raw = Files.readAllBytes(rememberTokenFile);
            byte[] plain = decodeStoredContent(raw);
            Properties props = new Properties();
            try (InputStream in = new ByteArrayInputStream(plain)) {
                props.load(in);
            }
            loadTokensFromProperties(props);

            if (rememberTokenKey != null && !startsWithEncryptedHeader(raw)) {
                saveRememberTokens();
            }
        } catch (Exception ex) {
            quarantineUnreadableTokenFile(ex);
            rememberTokens.clear();
        }
    }

    private synchronized void saveRememberTokens() {
        try {
            if (rememberTokenFile.getParent() != null) {
                Files.createDirectories(rememberTokenFile.getParent());
            }
            Properties props = new Properties();
            for (Map.Entry<UUID, String> entry : rememberTokens.entrySet()) {
                props.setProperty(entry.getKey().toString(), entry.getValue());
            }

            byte[] plain = toPropertiesBytes(props);
            byte[] stored = encodeStoredContent(plain);

            try (OutputStream out = Files.newOutputStream(rememberTokenFile)) {
                out.write(stored);
            }
        } catch (Exception ex) {
            if (logger != null) {
                logger.log(Level.WARNING, "Failed to persist remember tokens to " + rememberTokenFile, ex);
            }
        }
    }

    private void loadTokensFromProperties(Properties props) {
        for (String key : props.stringPropertyNames()) {
            try {
                UUID uuid = UUID.fromString(key);
                String token = props.getProperty(key);
                if (token != null && !token.trim().isEmpty()) {
                    rememberTokens.put(uuid, token);
                }
            } catch (IllegalArgumentException ignored) {
                // Skip invalid UUID entries.
            }
        }
    }

    private byte[] toPropertiesBytes(Properties props) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        props.store(bos, "MoontrixLogin remember tokens");
        return bos.toByteArray();
    }

    private byte[] encodeStoredContent(byte[] plain) throws Exception {
        if (rememberTokenKey == null) {
            return plain;
        }
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, rememberTokenKey, new GCMParameterSpec(128, iv));
        byte[] cipher = aes.doFinal(plain);

        byte[] payload = new byte[iv.length + cipher.length];
        System.arraycopy(iv, 0, payload, 0, iv.length);
        System.arraycopy(cipher, 0, payload, iv.length, cipher.length);

        String content = ENCRYPTED_HEADER + Base64.getEncoder().encodeToString(payload);
        return content.getBytes(StandardCharsets.UTF_8);
    }

    private byte[] decodeStoredContent(byte[] stored) throws Exception {
        if (!startsWithEncryptedHeader(stored)) {
            return stored;
        }
        if (rememberTokenKey == null) {
            throw new IllegalStateException("Remember token file is encrypted but no key is available.");
        }

        String body = new String(stored, StandardCharsets.UTF_8).substring(ENCRYPTED_HEADER.length()).trim();
        byte[] payload = Base64.getDecoder().decode(body);
        if (payload.length <= 12) {
            throw new IllegalStateException("Invalid remember token payload.");
        }

        byte[] iv = new byte[12];
        byte[] cipher = new byte[payload.length - 12];
        System.arraycopy(payload, 0, iv, 0, iv.length);
        System.arraycopy(payload, iv.length, cipher, 0, cipher.length);

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, rememberTokenKey, new GCMParameterSpec(128, iv));
        return aes.doFinal(cipher);
    }

    private boolean startsWithEncryptedHeader(byte[] data) {
        byte[] header = ENCRYPTED_HEADER.getBytes(StandardCharsets.UTF_8);
        if (data.length < header.length) {
            return false;
        }
        for (int i = 0; i < header.length; i++) {
            if (data[i] != header[i]) {
                return false;
            }
        }
        return true;
    }

    private SecretKey deriveAesKey(String sourceSecret) {
        if (sourceSecret == null || sourceSecret.trim().isEmpty()) {
            return null;
        }
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = sha256.digest(sourceSecret.getBytes(StandardCharsets.UTF_8));
            return new SecretKeySpec(keyBytes, "AES");
        } catch (Exception ex) {
            return null;
        }
    }

    private void quarantineUnreadableTokenFile(Exception ex) {
        if (logger != null) {
            logger.log(Level.WARNING,
                "Remember token file could not be read/decrypted. Stored remember sessions will be invalidated.",
                ex
            );
        }
        try {
            String suffix = ".invalid-" + System.currentTimeMillis();
            Path quarantine = rememberTokenFile.resolveSibling(rememberTokenFile.getFileName() + suffix);
            Files.move(rememberTokenFile, quarantine);
            if (logger != null) {
                logger.warning("Moved unreadable remember token file to: " + quarantine);
            }
        } catch (Exception moveEx) {
            try {
                Files.deleteIfExists(rememberTokenFile);
                if (logger != null) {
                    logger.warning("Deleted unreadable remember token file: " + rememberTokenFile);
                }
            } catch (Exception deleteEx) {
                if (logger != null) {
                    logger.log(Level.WARNING,
                        "Failed to quarantine or delete unreadable remember token file: " + rememberTokenFile,
                        deleteEx
                    );
                }
            }
        }
    }
}


