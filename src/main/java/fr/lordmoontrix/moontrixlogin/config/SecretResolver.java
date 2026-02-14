package fr.lordmoontrix.moontrixlogin.config;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class SecretResolver {
    private static final Pattern ENV_PATTERN = Pattern.compile("^\\$\\{ENV:([^}]+)}$");
    private static final Pattern AES_PATTERN = Pattern.compile("^\\$\\{AES_GCM:([^}]+)}$");
    private static final Pattern VAULT_PATTERN = Pattern.compile("^\\$\\{VAULT:([^#}]+)#([^}]+)}$");
    private static final String AES_KEY_ENV = "MOONTRIX_CONFIG_AES_KEY";
    private static final String VAULT_ADDR_ENV = "MOONTRIX_VAULT_ADDR";
    private static final String VAULT_TOKEN_ENV = "MOONTRIX_VAULT_TOKEN";
    private static final ObjectMapper JSON = new ObjectMapper();

    private final HttpClient httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(3))
        .build();

    String resolve(String configuredValue, String fallbackEnvKey) {
        String raw = configuredValue == null ? "" : configuredValue.trim();
        if (raw.isEmpty() && fallbackEnvKey != null && !fallbackEnvKey.isBlank()) {
            String env = readEnvOrProperty(fallbackEnvKey);
            return env == null ? "" : env;
        }

        Matcher envMatcher = ENV_PATTERN.matcher(raw);
        if (envMatcher.matches()) {
            String env = readEnvOrProperty(envMatcher.group(1).trim());
            return env == null ? "" : env;
        }

        Matcher aesMatcher = AES_PATTERN.matcher(raw);
        if (aesMatcher.matches()) {
            return decryptAesGcm(aesMatcher.group(1).trim(), configuredValue);
        }

        Matcher vaultMatcher = VAULT_PATTERN.matcher(raw);
        if (vaultMatcher.matches()) {
            return readVaultSecret(vaultMatcher.group(1).trim(), vaultMatcher.group(2).trim(), configuredValue);
        }

        if (fallbackEnvKey != null && !fallbackEnvKey.isBlank()) {
            String env = readEnvOrProperty(fallbackEnvKey);
            if (env != null && !env.isBlank()) {
                return env;
            }
        }
        return raw;
    }

    private String decryptAesGcm(String payload, String reference) {
        String keyB64 = readEnvOrProperty(AES_KEY_ENV);
        if (keyB64 == null || keyB64.isBlank()) {
            throw new IllegalStateException("Missing " + AES_KEY_ENV + " for secret " + reference);
        }
        try {
            byte[] keyBytes = Base64.getDecoder().decode(keyB64);
            SecretKey key = new SecretKeySpec(keyBytes, "AES");

            byte[] packed;
            if (payload.contains(":")) {
                String[] parts = payload.split(":", 2);
                byte[] iv = Base64.getDecoder().decode(parts[0]);
                byte[] cipher = Base64.getDecoder().decode(parts[1]);
                packed = ByteBuffer.allocate(iv.length + cipher.length).put(iv).put(cipher).array();
            } else {
                packed = Base64.getDecoder().decode(payload);
            }
            if (packed.length <= 12) {
                throw new IllegalStateException("Invalid AES payload for secret " + reference);
            }
            byte[] iv = new byte[12];
            byte[] cipher = new byte[packed.length - 12];
            System.arraycopy(packed, 0, iv, 0, iv.length);
            System.arraycopy(packed, iv.length, cipher, 0, cipher.length);

            Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
            aes.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] plain = aes.doFinal(cipher);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to decrypt secret " + reference, ex);
        }
    }

    private String readVaultSecret(String path, String field, String reference) {
        String addr = readEnvOrProperty(VAULT_ADDR_ENV);
        String token = readEnvOrProperty(VAULT_TOKEN_ENV);
        if (addr == null || token == null || addr.isBlank() || token.isBlank()) {
            throw new IllegalStateException(
                "Missing " + VAULT_ADDR_ENV + " or " + VAULT_TOKEN_ENV + " for secret " + reference
            );
        }
        String url = trimTrailingSlash(addr) + "/v1/" + path;
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .GET()
                .header("X-Vault-Token", token)
                .timeout(Duration.ofSeconds(4))
                .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IllegalStateException(
                    "Vault returned status " + response.statusCode() + " for secret " + reference
                );
            }
            return extractFieldValue(response.body(), field);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to resolve Vault secret " + reference, ex);
        }
    }

    private String extractFieldValue(String json, String field) {
        try {
            JsonNode root = JSON.readTree(json);
            JsonNode data = root.path("data").path("data");
            if (data.isMissingNode()) {
                data = root.path("data");
            }
            JsonNode value = data.path(field);
            if (value.isMissingNode() || value.isNull()) {
                throw new IllegalStateException("Vault response missing field '" + field + "'");
            }
            return value.asText();
        } catch (Exception ex) {
            throw new IllegalStateException("Invalid Vault response payload", ex);
        }
    }

    static String encryptToAesGcmReference(String plainText, String base64Key) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            SecretKey key = new SecretKeySpec(keyBytes, "AES");
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
            aes.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] cipher = aes.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            byte[] packed = ByteBuffer.allocate(iv.length + cipher.length).put(iv).put(cipher).array();
            return "${AES_GCM:" + Base64.getEncoder().encodeToString(packed) + "}";
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to encrypt secret", ex);
        }
    }

    private String readEnvOrProperty(String key) {
        String env = System.getenv(key);
        if (env != null) {
            return env;
        }
        return System.getProperty(key);
    }

    private String trimTrailingSlash(String value) {
        int end = value.length();
        while (end > 0 && value.charAt(end - 1) == '/') {
            end--;
        }
        return value.substring(0, end);
    }
}
