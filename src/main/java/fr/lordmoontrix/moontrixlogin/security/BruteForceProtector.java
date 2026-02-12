package fr.lordmoontrix.moontrixlogin.security;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class BruteForceProtector {
    private final int maxAttempts;
    private final long windowMillis;
    private final long lockMillis;
    private final Map<String, AttemptTracker> trackers = new ConcurrentHashMap<>();

    public BruteForceProtector(int maxAttempts, int windowSeconds, int lockSeconds) {
        this.maxAttempts = maxAttempts;
        this.windowMillis = windowSeconds * 1000L;
        this.lockMillis = lockSeconds * 1000L;
    }

    public boolean isLocked(String key) {
        AttemptTracker tracker = trackers.get(key);
        if (tracker == null) {
            return false;
        }
        return tracker.isLocked();
    }

    public long lockRemainingMillis(String key) {
        AttemptTracker tracker = trackers.get(key);
        if (tracker == null) {
            return 0L;
        }
        return tracker.lockRemainingMillis();
    }

    public void recordFailure(String key) {
        trackers.compute(key, (k, v) -> {
            if (v == null) {
                v = new AttemptTracker();
            }
            v.recordFailure(maxAttempts, windowMillis, lockMillis);
            return v;
        });
    }

    public boolean isLockedNow(String key) {
        AttemptTracker tracker = trackers.get(key);
        return tracker != null && tracker.isLocked();
    }

    public void recordSuccess(String key) {
        trackers.remove(key);
    }

    private static final class AttemptTracker {
        private final Deque<Long> attempts = new ArrayDeque<>();
        private long lockedUntil = 0L;

        void recordFailure(int maxAttempts, long windowMillis, long lockMillis) {
            long now = Instant.now().toEpochMilli();
            if (lockedUntil > now) {
                return;
            }
            attempts.addLast(now);
            trimOld(now, windowMillis);
            if (attempts.size() >= maxAttempts) {
                lockedUntil = now + lockMillis;
                attempts.clear();
            }
        }

        boolean isLocked() {
            return Instant.now().toEpochMilli() < lockedUntil;
        }

        long lockRemainingMillis() {
            long now = Instant.now().toEpochMilli();
            return Math.max(0L, lockedUntil - now);
        }

        private void trimOld(long now, long windowMillis) {
            while (!attempts.isEmpty() && now - attempts.peekFirst() > windowMillis) {
                attempts.removeFirst();
            }
        }
    }
}
