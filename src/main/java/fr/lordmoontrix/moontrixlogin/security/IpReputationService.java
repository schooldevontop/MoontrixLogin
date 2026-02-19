package fr.lordmoontrix.moontrixlogin.security;

import fr.lordmoontrix.moontrixlogin.config.PluginConfig;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class IpReputationService {
    private static final Pattern SCORE_PATTERN = Pattern.compile("\"abuseConfidenceScore\"\\s*:\\s*(\\d+)");

    private final PluginConfig.AntiBot config;
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<String, CacheEntry>();
    private final Set<String> refreshInFlight = ConcurrentHashMap.newKeySet();
    private final ExecutorService refresher = Executors.newFixedThreadPool(2);

    public IpReputationService(PluginConfig.AntiBot config) {
        this.config = config;
    }

    public boolean isSuspicious(String ip) {
        if (!config.isAbuseIpDbEnabled()) {
            return false;
        }
        if (ip == null || ip.trim().isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            return false;
        }
        CacheEntry cached = cache.get(ip);
        long now = Instant.now().toEpochMilli();
        if (cached != null && cached.expiresAtMillis > now) {
            return cached.suspicious;
        }
        triggerRefresh(ip);
        return cached != null && cached.suspicious;
    }

    private FetchResult fetchSuspicious(String ip) {
        int failureTtl = Math.max(30, config.getAbuseIpDbFailureBackoffSeconds());
        int successTtl = Math.max(60, config.getAbuseIpDbCacheSeconds());

        if (config.getAbuseIpDbApiKey() == null || config.getAbuseIpDbApiKey().trim().isEmpty()) {
            return new FetchResult(false, failureTtl);
        }

        HttpURLConnection connection = null;
        try {
            String url = "https://api.abuseipdb.com/api/v2/check?ipAddress="
                + URLEncoder.encode(ip, "UTF-8")
                + "&maxAgeInDays=" + Math.max(1, config.getAbuseIpDbMaxAgeDays());

            connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(Math.max(500, config.getAbuseIpDbRequestTimeoutMs()));
            connection.setReadTimeout(Math.max(500, config.getAbuseIpDbRequestTimeoutMs()));
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("Key", config.getAbuseIpDbApiKey());

            int status = connection.getResponseCode();
            if (status == 429) {
                return new FetchResult(false, parseRetryAfterSeconds(connection, failureTtl));
            }
            if (status < 200 || status >= 300) {
                return new FetchResult(false, failureTtl);
            }

            String body = readBody(connection.getInputStream());
            Matcher matcher = SCORE_PATTERN.matcher(body);
            if (!matcher.find()) {
                return new FetchResult(false, failureTtl);
            }
            int score = Integer.parseInt(matcher.group(1));
            return new FetchResult(score >= config.getAbuseIpDbMinConfidenceScore(), successTtl);
        } catch (Exception ex) {
            return new FetchResult(false, failureTtl);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private String readBody(InputStream stream) throws Exception {
        if (stream == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        byte[] buffer = new byte[2048];
        int read;
        while ((read = stream.read(buffer)) != -1) {
            sb.append(new String(buffer, 0, read, "UTF-8"));
        }
        return sb.toString();
    }

    private int parseRetryAfterSeconds(HttpURLConnection connection, int fallback) {
        try {
            String value = connection.getHeaderField("Retry-After");
            if (value == null || value.trim().isEmpty()) {
                return fallback;
            }
            return Math.max(30, Integer.parseInt(value.trim()));
        } catch (Exception ex) {
            return fallback;
        }
    }

    private void triggerRefresh(String ip) {
        if (!refreshInFlight.add(ip)) {
            return;
        }
        try {
            refresher.execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        FetchResult result = fetchSuspicious(ip);
                        long now = Instant.now().toEpochMilli();
                        cache.put(ip, new CacheEntry(result.suspicious, now + result.cacheSeconds * 1000L));
                    } finally {
                        refreshInFlight.remove(ip);
                    }
                }
            });
        } catch (RejectedExecutionException ex) {
            refreshInFlight.remove(ip);
        }
    }

    public void shutdown() {
        refresher.shutdown();
    }

    private static final class FetchResult {
        private final boolean suspicious;
        private final int cacheSeconds;

        private FetchResult(boolean suspicious, int cacheSeconds) {
            this.suspicious = suspicious;
            this.cacheSeconds = cacheSeconds;
        }
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

