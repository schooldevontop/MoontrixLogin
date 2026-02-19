package fr.lordmoontrix.moontrixlogin.listener;

import fr.lordmoontrix.moontrixlogin.config.PluginConfig;
import fr.lordmoontrix.moontrixlogin.model.AuthState;
import fr.lordmoontrix.moontrixlogin.security.AntiBotService;
import fr.lordmoontrix.moontrixlogin.service.CaptchaService;
import fr.lordmoontrix.moontrixlogin.service.MessageService;
import fr.lordmoontrix.moontrixlogin.session.SessionManager;
import fr.lordmoontrix.moontrixlogin.util.SchedulerUtil;
import java.util.Locale;
import java.util.Set;
import org.bukkit.Location;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.plugin.Plugin;

public final class PlayerProtectionListener implements Listener {
    private final Plugin plugin;
    private final SessionManager sessionManager;
    private final PluginConfig.Protection protection;
    private final MessageService messages;
    private final CaptchaService captchaService;
    private final AntiBotService antiBotService;

    public PlayerProtectionListener(Plugin plugin, SessionManager sessionManager, PluginConfig.Protection protection,
                                    MessageService messages, CaptchaService captchaService,
                                    AntiBotService antiBotService) {
        this.plugin = plugin;
        this.sessionManager = sessionManager;
        this.protection = protection;
        this.messages = messages;
        this.captchaService = captchaService;
        this.antiBotService = antiBotService;
    }

    @EventHandler(priority = EventPriority.HIGH, ignoreCancelled = true)
    public void onChat(AsyncPlayerChatEvent event) {
        if (!protection.isBlockChatBeforeLogin()) {
            return;
        }
        if (!isAuthenticated(event.getPlayer())) {
            event.setCancelled(true);
            SchedulerUtil.runAtPlayer(plugin, event.getPlayer(),
                () -> event.getPlayer().sendMessage(messages.get("error.denied_chat", "You must login first.")));
        }
    }

    @EventHandler(priority = EventPriority.HIGH, ignoreCancelled = true)
    public void onCommand(PlayerCommandPreprocessEvent event) {
        if (!protection.isBlockCommandsBeforeLogin()) {
            return;
        }
        Player player = event.getPlayer();
        if (isAuthenticated(player)) {
            return;
        }
        String msg = event.getMessage();
        String cmd = msg.startsWith("/") ? msg.substring(1) : msg;
        String root = cmd.split(" ")[0].toLowerCase(Locale.ROOT);
        Set<String> allowed = protection.getAllowedCommands();
        if (!allowed.contains(root)) {
            event.setCancelled(true);
            player.sendMessage(messages.get("error.denied_command", "You must login first."));
        }
    }

    @EventHandler(priority = EventPriority.HIGH, ignoreCancelled = true)
    public void onMove(PlayerMoveEvent event) {
        if (!protection.isBlockMovementBeforeLogin()) {
            return;
        }
        if (isAuthenticated(event.getPlayer())) {
            return;
        }
        if (event.getPlayer().getAddress() != null) {
            String ip = event.getPlayer().getAddress().getAddress().getHostAddress();
            if (antiBotService.isShadowBanned(ip)) {
                event.setCancelled(true);
                event.getPlayer().sendMessage(messages.get("error.shadow_ban",
                    "Login temporarily restricted."));
                return;
            }
        }
        if (captchaService.hasPending(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
            return;
        }
        Location from = event.getFrom();
        Location to = event.getTo();
        if (to != null && (from.getBlockX() != to.getBlockX()
            || from.getBlockY() != to.getBlockY()
            || from.getBlockZ() != to.getBlockZ())) {
            event.setTo(from);
        }
    }

    private boolean isAuthenticated(Player player) {
        if (captchaService.hasPending(player.getUniqueId())) {
            return false;
        }
        return sessionManager.get(player.getUniqueId())
            .map(session -> session.getState() == AuthState.AUTHENTICATED)
            .orElse(false);
    }
}


