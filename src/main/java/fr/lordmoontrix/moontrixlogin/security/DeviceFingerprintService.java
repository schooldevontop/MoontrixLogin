package fr.lordmoontrix.moontrixlogin.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Locale;
import java.util.UUID;
import org.bukkit.entity.Player;

public final class DeviceFingerprintService {
    public String fingerprint(Player player, String ip, int ipPrefixSegments) {
        String normalizedIp = normalizeIpPrefix(ip, ipPrefixSegments);
        String locale = safe(readLocale(player));
        String brand = safe(readClientBrand(player));
        String source = player.getUniqueId() + "|" + normalizedIp + "|" + locale + "|" + brand;
        return hash(source);
    }

    public String normalizeIpPrefix(String ip, int ipPrefixSegments) {
        if (ip == null) {
            return "unknown";
        }
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return ip;
        }
        int segments = Math.max(1, Math.min(4, ipPrefixSegments));
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < segments; i++) {
            if (i > 0) {
                sb.append('.');
            }
            sb.append(parts[i]);
        }
        return sb.toString();
    }

    private String readClientBrand(Player player) {
        try {
            java.lang.reflect.Method m = player.getClass().getMethod("getClientBrandName");
            Object value = m.invoke(player);
            return value == null ? "unknown" : value.toString();
        } catch (Exception ignored) {
            return "unknown";
        }
    }

    private String readLocale(Player player) {
        try {
            java.lang.reflect.Method m = player.getClass().getMethod("getLocale");
            Object value = m.invoke(player);
            return value == null ? "unknown" : value.toString();
        } catch (Exception ignored) {
            return "unknown";
        }
    }

    private String safe(String value) {
        if (value == null || value.trim().isEmpty()) {
            return "unknown";
        }
        return value.toLowerCase(Locale.ROOT);
    }

    private String hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashed);
        } catch (Exception ex) {
            return UUID.randomUUID().toString();
        }
    }
}


