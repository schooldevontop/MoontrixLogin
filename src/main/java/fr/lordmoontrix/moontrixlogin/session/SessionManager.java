package fr.lordmoontrix.moontrixlogin.session;

import fr.lordmoontrix.moontrixlogin.model.AuthState;
import fr.lordmoontrix.moontrixlogin.model.Session;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class SessionManager {
    private final Map<UUID, Session> sessions = new ConcurrentHashMap<>();
    private final Duration timeout;

    public SessionManager(Duration timeout) {
        this.timeout = timeout;
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

    public boolean isIpChanged(UUID uuid, String currentIp) {
        return get(uuid).map(s -> s.getLastIp() != null && !s.getLastIp().equals(currentIp)).orElse(false);
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
}
