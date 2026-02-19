package fr.lordmoontrix.moontrixlogin.listener;

import fr.lordmoontrix.moontrixlogin.model.AuthState;
import fr.lordmoontrix.moontrixlogin.service.CaptchaService;
import fr.lordmoontrix.moontrixlogin.service.MessageService;
import fr.lordmoontrix.moontrixlogin.session.SessionManager;
import fr.lordmoontrix.moontrixlogin.storage.UserRepository;
import fr.lordmoontrix.moontrixlogin.security.AntiBotService;
import fr.lordmoontrix.moontrixlogin.security.DeviceFingerprintService;
import fr.lordmoontrix.moontrixlogin.session.JwtSessionTokenService;
import fr.lordmoontrix.moontrixlogin.util.SchedulerUtil;
import java.util.UUID;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerKickEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.Plugin;

public final class PlayerConnectionListener implements Listener {
    private final Plugin plugin;
    private final UserRepository userRepository;
    private final SessionManager sessionManager;
    private final MessageService messages;
    private final CaptchaService captchaService;
    private final boolean captchaEnabled;
    private final AntiBotService antiBotService;
    private final boolean invalidateOnIpChange;
    private final int ipPrefixSegments;
    private final int loginTimeoutSeconds;
    private final boolean kickOnTimeout;
    private final DeviceFingerprintService fingerprintService;
    private final JwtSessionTokenService jwtSessionTokenService;
    private final boolean rememberMeEnabled;

    public PlayerConnectionListener(Plugin plugin, UserRepository userRepository,
                                    SessionManager sessionManager, MessageService messages,
                                    CaptchaService captchaService, boolean captchaEnabled,
                                    AntiBotService antiBotService, boolean invalidateOnIpChange,
                                    int ipPrefixSegments, int loginTimeoutSeconds, boolean kickOnTimeout,
                                    DeviceFingerprintService fingerprintService,
                                    JwtSessionTokenService jwtSessionTokenService,
                                    boolean rememberMeEnabled) {
        this.plugin = plugin;
        this.userRepository = userRepository;
        this.sessionManager = sessionManager;
        this.messages = messages;
        this.captchaService = captchaService;
        this.captchaEnabled = captchaEnabled;
        this.antiBotService = antiBotService;
        this.invalidateOnIpChange = invalidateOnIpChange;
        this.ipPrefixSegments = ipPrefixSegments;
        this.loginTimeoutSeconds = loginTimeoutSeconds;
        this.kickOnTimeout = kickOnTimeout;
        this.fingerprintService = fingerprintService;
        this.jwtSessionTokenService = jwtSessionTokenService;
        this.rememberMeEnabled = rememberMeEnabled;
    }

    @EventHandler
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        UUID uuid = player.getUniqueId();
        String playerName = player.getName();
        boolean playedBefore = player.hasPlayedBefore();
        String ip = player.getAddress() != null
            ? player.getAddress().getAddress().getHostAddress()
            : "unknown";
        String fingerprint = fingerprintService.fingerprint(player, ip, ipPrefixSegments);
        userRepository.findByUuid(uuid).thenAccept(optional -> {
            AuthState state = optional.isPresent() ? AuthState.UNAUTHENTICATED : AuthState.UNREGISTERED;
            boolean contextChanged = optional
                .map(record -> isContextChanged(uuid, record.getLastIp(), ip, fingerprint))
                .orElse(false);
            sessionManager.setState(uuid, contextChanged ? AuthState.UNAUTHENTICATED : state);
            if (!playedBefore) {
                antiBotService.recordNewPlayerJoin(ip, playerName);
            }
            if (contextChanged) {
                sessionManager.clearRememberToken(uuid);
            }
            boolean remembered = rememberMeEnabled && attemptRemember(uuid, fingerprint, ip);
            SchedulerUtil.runGlobal(plugin, () -> {
                Player online = Bukkit.getPlayer(uuid);
                if (online == null) {
                    return;
                }
                boolean finalContextChanged = contextChanged;
                SchedulerUtil.runAtPlayer(plugin, online, () -> {
                    if (!online.isOnline()) {
                        return;
                    }
                    if (finalContextChanged) {
                        online.sendMessage(messages.get("error.ip_changed",
                            "Your session was invalidated due to IP change."));
                    }
                    if (remembered) {
                        online.sendMessage(messages.get("login.success", "Logged in."));
                        return;
                    }
                    if (state == AuthState.UNREGISTERED) {
                        online.sendMessage(messages.get("registration.register_request",
                            "Please register using /register <password> [verifyPassword]."));
                    } else {
                        online.sendMessage(messages.get("login.login_request", "Please login using /login <password>."));
                    }
                    if (captchaEnabled) {
                        String code = captchaService.create(uuid);
                        String template = messages.get("captcha.message", "Captcha: %code%");
                        online.sendMessage(template.replace("%code%", code));
                    }
                });
                if (loginTimeoutSeconds > 0) {
                    SchedulerUtil.runAtPlayerLater(plugin, online, () -> {
                        if (!online.isOnline()) {
                            return;
                        }
                        boolean authed = sessionManager.get(uuid)
                            .map(s -> s.getState() == AuthState.AUTHENTICATED).orElse(false);
                        if (!authed) {
                            String msg = messages.get("login.timeout_error", "Login timed out.");
                            if (kickOnTimeout) {
                                online.kickPlayer(msg);
                            } else {
                                online.sendMessage(msg);
                            }
                        }
                    }, loginTimeoutSeconds * 20L);
                }
            });
        }).exceptionally(ex -> {
            plugin.getLogger().severe("Failed to load user data for " + playerName + ": " + ex.getMessage());
            sessionManager.setState(uuid, AuthState.UNAUTHENTICATED);
            return null;
        });
    }

    private boolean isContextChanged(UUID uuid, String lastIp, String currentIp, String fingerprint) {
        if (!invalidateOnIpChange || "unknown".equals(currentIp) || lastIp == null) {
            return false;
        }
        String previousPrefix = fingerprintService.normalizeIpPrefix(lastIp, ipPrefixSegments);
        String currentPrefix = fingerprintService.normalizeIpPrefix(currentIp, ipPrefixSegments);
        if (!previousPrefix.equals(currentPrefix)) {
            return true;
        }
        if (!rememberMeEnabled || jwtSessionTokenService == null) {
            return false;
        }
        return sessionManager.getRememberToken(uuid)
            .flatMap(jwtSessionTokenService::validateRememberToken)
            .filter(claims -> claims.uuid().equals(uuid))
            .map(claims -> !claims.fingerprint().equals(fingerprint))
            .orElse(false);
    }

    private boolean attemptRemember(UUID uuid, String fingerprint, String ip) {
        if (jwtSessionTokenService == null) {
            return false;
        }
        return sessionManager.getRememberToken(uuid)
            .flatMap(jwtSessionTokenService::validateRememberToken)
            .filter(claims -> claims.uuid().equals(uuid))
            .filter(claims -> claims.fingerprint().equals(fingerprint))
            .filter(claims -> claims.ipPrefix().equals(
                fingerprintService.normalizeIpPrefix(ip, ipPrefixSegments)))
            .map(claims -> {
                sessionManager.markAuthenticated(uuid, ip, fingerprint);
                return true;
            })
            .orElse(false);
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        sessionManager.remove(event.getPlayer().getUniqueId());
    }

    @EventHandler
    public void onKick(PlayerKickEvent event) {
        sessionManager.remove(event.getPlayer().getUniqueId());
    }
}


