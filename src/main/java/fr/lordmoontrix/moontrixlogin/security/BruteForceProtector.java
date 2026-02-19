package fr.lordmoontrix.moontrixlogin.security;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class BruteForceProtector {
    private final int maxAttempts;
    private final long windowMillis;
    private final long[] lockScheduleMillis;
    private final Map<String, AttemptTracker> trackers = new ConcurrentHashMap<>();

    public BruteForceProtector(int maxAttempts, int windowSeconds, int lockSeconds) {
        this(maxAttempts, windowSeconds, new int[] {lockSeconds});
    }

    public BruteForceProtector(int maxAttempts, int windowSeconds, int[] progressiveLockSeconds) {
        this.maxAttempts = Math.max(1, maxAttempts);
        this.windowMillis = Math.max(1, windowSeconds) * 1000L;
        this.lockScheduleMillis = toLockSchedule(progressiveLockSeconds);
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
        trackers.compute(key, (k, tracker) -> {
            AttemptTracker current = tracker == null ? new AttemptTracker() : tracker;
            current.recordFailure(maxAttempts, windowMillis, lockScheduleMillis);
            return current;
        });
    }

    public boolean isLockedNow(String key) {
        AttemptTracker tracker = trackers.get(key);
        return tracker != null && tracker.isLocked();
    }

    public void recordSuccess(String key) {
        trackers.remove(key);
    }

    private long[] toLockSchedule(int[] progressiveLockSeconds) {
        if (progressiveLockSeconds == null || progressiveLockSeconds.length == 0) {
            return new long[] {600_000L};
        }
        long[] schedule = new long[progressiveLockSeconds.length];
        for (int i = 0; i < progressiveLockSeconds.length; i++) {
            if (progressiveLockSeconds[i] <= 0) {
                schedule[i] = -1L;
            } else {
                schedule[i] = Math.max(1, progressiveLockSeconds[i]) * 1000L;
            }
        }
        return schedule;
    }

    private static final class AttemptTracker {
        private final Deque<Long> attempts = new ArrayDeque<>();
        private long lockedUntil = 0L;
        private int strikeLevel = 0;
        private long lastLockExpiredAt = 0L;

        synchronized void recordFailure(int maxAttempts, long windowMillis, long[] lockScheduleMillis) {
            long now = Instant.now().toEpochMilli();
            if (lockedUntil > now) {
                return;
            }

            if (lastLockExpiredAt > 0 && now - lastLockExpiredAt > windowMillis * 2L) {
                strikeLevel = Math.max(0, strikeLevel - 1);
                lastLockExpiredAt = 0L;
            }

            attempts.addLast(now);
            trimOld(now, windowMillis);
            if (attempts.size() >= maxAttempts) {
                int idx = Math.min(strikeLevel, lockScheduleMillis.length - 1);
                long lockMillis = lockScheduleMillis[idx];
                if (lockMillis < 0L) {
                    lockedUntil = Long.MAX_VALUE;
                    lastLockExpiredAt = now;
                } else {
                    lockedUntil = now + lockMillis;
                    lastLockExpiredAt = lockedUntil;
                }
                attempts.clear();
                if (strikeLevel < lockScheduleMillis.length - 1) {
                    strikeLevel++;
                }
            }
        }

        synchronized boolean isLocked() {
            return Instant.now().toEpochMilli() < lockedUntil;
        }

        synchronized long lockRemainingMillis() {
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


