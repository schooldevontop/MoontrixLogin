package fr.lordmoontrix.moontrixlogin.listener;

import fr.lordmoontrix.moontrixlogin.model.AuthState;
import fr.lordmoontrix.moontrixlogin.service.CaptchaService;
import fr.lordmoontrix.moontrixlogin.service.MessageService;
import fr.lordmoontrix.moontrixlogin.session.SessionManager;
import fr.lordmoontrix.moontrixlogin.storage.UserRepository;
import fr.lordmoontrix.moontrixlogin.security.AntiBotService;
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

    public PlayerConnectionListener(Plugin plugin, UserRepository userRepository,
                                    SessionManager sessionManager, MessageService messages,
                                    CaptchaService captchaService, boolean captchaEnabled,
                                    AntiBotService antiBotService) {
        this.plugin = plugin;
        this.userRepository = userRepository;
        this.sessionManager = sessionManager;
        this.messages = messages;
        this.captchaService = captchaService;
        this.captchaEnabled = captchaEnabled;
        this.antiBotService = antiBotService;
    }

    @EventHandler
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        UUID uuid = player.getUniqueId();
        userRepository.findByUuid(uuid).thenAccept(optional -> {
            AuthState state = optional.isPresent() ? AuthState.UNAUTHENTICATED : AuthState.UNREGISTERED;
            sessionManager.setState(uuid, state);
            if (!event.getPlayer().hasPlayedBefore()) {
                String ip = event.getPlayer().getAddress() != null
                    ? event.getPlayer().getAddress().getAddress().getHostAddress()
                    : "unknown";
                antiBotService.recordNewPlayerJoin(ip, event.getPlayer().getName());
            }
            if (event.getPlayer().getAddress() != null) {
                String currentIp = event.getPlayer().getAddress().getAddress().getHostAddress();
                if (sessionManager.isIpChanged(uuid, currentIp)) {
                    sessionManager.setState(uuid, AuthState.UNAUTHENTICATED);
                    Bukkit.getScheduler().runTask(plugin, () ->
                        event.getPlayer().sendMessage(messages.get("error.ip_changed",
                            "Your session was invalidated due to IP change.")));
                }
            }
            Bukkit.getScheduler().runTask(plugin, () -> {
                if (!player.isOnline()) {
                    return;
                }
                if (state == AuthState.UNREGISTERED) {
                    player.sendMessage(messages.get("registration.register_request",
                        "Please register using /register <password> <verifyPassword>."));
                } else {
                    player.sendMessage(messages.get("login.login_request", "Please login using /login <password>."));
                }
                if (captchaEnabled) {
                    String code = captchaService.create(uuid);
                    String template = messages.get("captcha.message", "Captcha: %code%");
                    player.sendMessage(template.replace("%code%", code));
                }
            });
        }).exceptionally(ex -> {
            plugin.getLogger().severe("Failed to load user data for " + player.getName() + ": " + ex.getMessage());
            sessionManager.setState(uuid, AuthState.UNAUTHENTICATED);
            return null;
        });
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
