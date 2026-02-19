package fr.lordmoontrix.moontrixlogin.security;

import fr.lordmoontrix.moontrixlogin.config.PluginConfig;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public final class AntiBotService {
    public enum DecisionType {
        ALLOW,
        DELAY,
        CAPTCHA,
        SHADOW_BAN,
        LOCK,
        KICK
    }

    public static final class Decision {
        private final DecisionType type;
        private final int seconds;

        public Decision(DecisionType type, int seconds) {
            this.type = type;
            this.seconds = seconds;
        }

        public DecisionType getType() {
            return type;
        }

        public int getSeconds() {
            return seconds;
        }
    }

    private final PluginConfig.AntiBot config;
    private final IpReputationService ipReputationService;
    private final Map<String, IpState> ipStates = new ConcurrentHashMap<>();
    private final Map<String, Long> shadowBans = new ConcurrentHashMap<>();
    private final Map<String, Long> locks = new ConcurrentHashMap<>();
    private final Map<String, Integer> fingerprintFailures = new ConcurrentHashMap<>();
    private final Map<String, Long> fingerprintBans = new ConcurrentHashMap<>();

    public AntiBotService(PluginConfig.AntiBot config, IpReputationService ipReputationService) {
        this.config = config;
        this.ipReputationService = ipReputationService;
    }

    public void recordLoginAttempt(String ip, String username) {
        ipStates.computeIfAbsent(ip, k -> new IpState())
            .recordLogin(username, config.getLoginWindowSeconds(), config.getDistinctNamesWindowSeconds());
    }

    public void recordNewPlayerJoin(String ip, String username) {
        ipStates.computeIfAbsent(ip, k -> new IpState())
            .recordNewPlayer(username, config.getNewPlayerWindowSeconds());
    }

    public Decision evaluate(String ip, String fingerprint) {
        long now = Instant.now().toEpochMilli();
        if (isLocked(ip)) {
            return new Decision(DecisionType.LOCK, (int) ((locks.get(ip) - now) / 1000L));
        }
        if (isFingerprintBanned(fingerprint)) {
            return new Decision(DecisionType.LOCK, (int) ((fingerprintBans.get(fingerprint) - now) / 1000L));
        }
        if (ipReputationService.isSuspicious(ip)) {
            locks.put(ip, now + config.getBruteForceLockSeconds() * 1000L);
            return new Decision(DecisionType.CAPTCHA, config.getBruteForceLockSeconds());
        }
        if (isShadowBanned(ip)) {
            return new Decision(DecisionType.SHADOW_BAN, (int) ((shadowBans.get(ip) - now) / 1000L));
        }

        IpState state = ipStates.get(ip);
        if (state == null) {
            return new Decision(DecisionType.DELAY, config.getLoginDelaySeconds());
        }

        boolean suspicious = state.isSuspicious(config.getMaxLoginPerIpWindow(),
            config.getMaxDistinctNamesPerIpWindow(),
            config.getMaxNewPlayersPerIpWindow());

        if (suspicious) {
            shadowBans.put(ip, now + config.getShadowBanSeconds() * 1000L);
            if (config.isAdaptiveCaptchaEnabled()) {
                return new Decision(DecisionType.CAPTCHA, config.getSuspiciousDelaySeconds());
            }
            return new Decision(DecisionType.SHADOW_BAN, config.getShadowBanSeconds());
        }

        return new Decision(DecisionType.DELAY, config.getLoginDelaySeconds());
    }

    public void markBruteForce(String ip) {
        long now = Instant.now().toEpochMilli();
        locks.put(ip, now + config.getBruteForceLockSeconds() * 1000L);
    }

    public void recordFingerprintFailure(String fingerprint) {
        if (fingerprint == null || fingerprint.trim().isEmpty()) {
            return;
        }
        int count = fingerprintFailures.merge(fingerprint, 1, Integer::sum);
        if (count >= Math.max(3, config.getFingerprintBanThreshold())) {
            long banSeconds = Math.max(config.getBruteForceLockSeconds(), 3600);
            fingerprintBans.put(fingerprint, Instant.now().toEpochMilli() + banSeconds * 1000L);
            fingerprintFailures.put(fingerprint, 0);
        }
    }

    public void clearFingerprintFailure(String fingerprint) {
        if (fingerprint == null || fingerprint.trim().isEmpty()) {
            return;
        }
        fingerprintFailures.remove(fingerprint);
    }

    public boolean isFingerprintBanned(String fingerprint) {
        if (fingerprint == null || fingerprint.trim().isEmpty()) {
            return false;
        }
        Long until = fingerprintBans.get(fingerprint);
        if (until == null) {
            return false;
        }
        if (Instant.now().toEpochMilli() > until) {
            fingerprintBans.remove(fingerprint);
            return false;
        }
        return true;
    }

    public boolean isShadowBanned(String ip) {
        Long until = shadowBans.get(ip);
        if (until == null) {
            return false;
        }
        if (Instant.now().toEpochMilli() > until) {
            shadowBans.remove(ip);
            return false;
        }
        return true;
    }

    public boolean isLocked(String ip) {
        Long until = locks.get(ip);
        if (until == null) {
            return false;
        }
        if (Instant.now().toEpochMilli() > until) {
            locks.remove(ip);
            return false;
        }
        return true;
    }

    private static final class IpState {
        private final Deque<Long> loginAttempts = new ArrayDeque<>();
        private final Deque<LoginName> names = new ArrayDeque<>();
        private final Deque<Long> newPlayers = new ArrayDeque<>();

        void recordLogin(String username, int loginWindowSeconds, int distinctNamesWindowSeconds) {
            long now = Instant.now().toEpochMilli();
            loginAttempts.addLast(now);
            names.addLast(new LoginName(username, now));
            trim(loginAttempts, now - loginWindowSeconds * 1000L);
            trimNames(now - distinctNamesWindowSeconds * 1000L);
        }

        void recordNewPlayer(String username, int newPlayerWindowSeconds) {
            long now = Instant.now().toEpochMilli();
            newPlayers.addLast(now);
            trim(newPlayers, now - newPlayerWindowSeconds * 1000L);
        }

        boolean isSuspicious(int maxLoginPerWindow, int maxDistinctNames, int maxNewPlayers) {
            Set<String> distinct = new HashSet<>();
            for (LoginName ln : names) {
                distinct.add(ln.name);
            }
            return loginAttempts.size() >= maxLoginPerWindow
                || distinct.size() >= maxDistinctNames
                || newPlayers.size() >= maxNewPlayers;
        }

        private void trim(Deque<Long> deque, long threshold) {
            while (!deque.isEmpty() && deque.peekFirst() < threshold) {
                deque.removeFirst();
            }
        }

        private void trimNames(long threshold) {
            while (!names.isEmpty() && names.peekFirst().timestamp < threshold) {
                names.removeFirst();
            }
        }
    }

    private static final class LoginName {
        private final String name;
        private final long timestamp;

        private LoginName(String name, long timestamp) {
            this.name = name;
            this.timestamp = timestamp;
        }
    }
}


