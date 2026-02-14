package fr.lordmoontrix.moontrixlogin.security;

import fr.lordmoontrix.moontrixlogin.config.PluginConfig;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class IpReputationService {
    private static final Pattern SCORE_PATTERN = Pattern.compile("\"abuseConfidenceScore\"\\s*:\\s*(\\d+)");

    private final PluginConfig.AntiBot config;
    private final HttpClient client;
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private final ExecutorService refresher = Executors.newFixedThreadPool(2);

    public IpReputationService(PluginConfig.AntiBot config) {
        this.config = config;
        this.client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();
    }

    public boolean isSuspicious(String ip) {
        if (!config.isAbuseIpDbEnabled()) {
            return false;
        }
        if (ip == null || ip.isBlank() || "unknown".equalsIgnoreCase(ip)) {
            return false;
        }
        CacheEntry cached = cache.get(ip);
        long now = Instant.now().toEpochMilli();
        if (cached != null && cached.expiresAtMillis > now) {
            return cached.suspicious;
        }
        triggerRefresh(ip, now);
        return cached != null && cached.suspicious;
    }

    private boolean fetchSuspicious(String ip) {
        if (config.getAbuseIpDbApiKey() == null || config.getAbuseIpDbApiKey().isBlank()) {
            return false;
        }
        try {
            String url = "https://api.abuseipdb.com/api/v2/check?ipAddress="
                + URLEncoder.encode(ip, StandardCharsets.UTF_8)
                + "&maxAgeInDays=" + Math.max(1, config.getAbuseIpDbMaxAgeDays());

            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .GET()
                .timeout(Duration.ofSeconds(4))
                .header("Accept", "application/json")
                .header("Key", config.getAbuseIpDbApiKey())
                .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                return false;
            }
            Matcher matcher = SCORE_PATTERN.matcher(response.body());
            if (!matcher.find()) {
                return false;
            }
            int score = Integer.parseInt(matcher.group(1));
            return score >= config.getAbuseIpDbMinConfidenceScore();
        } catch (Exception ex) {
            return false;
        }
    }

    private void triggerRefresh(String ip, long now) {
        refresher.execute(() -> {
            boolean suspicious = fetchSuspicious(ip);
            cache.put(ip, new CacheEntry(
                suspicious,
                now + Math.max(60, config.getAbuseIpDbCacheSeconds()) * 1000L
            ));
        });
    }

    public void shutdown() {
        refresher.shutdown();
    }

    private static final class CacheEntry {
        private final boolean suspicious;
        private final long expiresAtMillis;

        private CacheEntry(boolean suspicious, long expiresAtMillis) {
            this.suspicious = suspicious;
            this.expiresAtMillis = expiresAtMillis;
        }
    }
}
