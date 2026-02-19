package fr.lordmoontrix.moontrixlogin.mail;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public final class EmailRateLimiter {
    private final int maxPerWindow;
    private final long windowMillis;
    private final long cooldownMillis;
    private final ConcurrentMap<String, State> states = new ConcurrentHashMap<>();

    public EmailRateLimiter(int maxPerWindow, int windowSeconds, int cooldownSeconds) {
        this.maxPerWindow = Math.max(1, maxPerWindow);
        this.windowMillis = Math.max(1000L, windowSeconds * 1000L);
        this.cooldownMillis = Math.max(0L, cooldownSeconds * 1000L);
    }

    public Result tryAcquire(String key) {
        long now = System.currentTimeMillis();
        State state = states.computeIfAbsent(key, k -> new State());
        synchronized (state) {
            if (now < state.cooldownUntil) {
                long retry = Math.max(1, (state.cooldownUntil - now + 999) / 1000);
                return Result.denied(retry);
            }
            purgeOld(state, now);
            if (state.timestamps.size() >= maxPerWindow) {
                state.cooldownUntil = now + cooldownMillis;
                long retry = Math.max(1, (state.cooldownUntil - now + 999) / 1000);
                return Result.denied(retry);
            }
            state.timestamps.addLast(now);
            return Result.allowed();
        }
    }

    private void purgeOld(State state, long now) {
        long cutoff = now - windowMillis;
        Deque<Long> deque = state.timestamps;
        while (!deque.isEmpty() && deque.peekFirst() < cutoff) {
            deque.removeFirst();
        }
    }

    private static final class State {
        private final Deque<Long> timestamps = new ArrayDeque<>();
        private long cooldownUntil;
    }

    public static final class Result {
        private final boolean allowed;
        private final long retryAfterSeconds;

        private Result(boolean allowed, long retryAfterSeconds) {
            this.allowed = allowed;
            this.retryAfterSeconds = retryAfterSeconds;
        }

        public static Result allowed() {
            return new Result(true, 0);
        }

        public static Result denied(long retryAfterSeconds) {
            return new Result(false, retryAfterSeconds);
        }

        public boolean isAllowed() {
            return allowed;
        }

        public long getRetryAfterSeconds() {
            return retryAfterSeconds;
        }
    }
}


