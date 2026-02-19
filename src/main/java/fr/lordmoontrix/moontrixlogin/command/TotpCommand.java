package fr.lordmoontrix.moontrixlogin.command;

import fr.lordmoontrix.moontrixlogin.model.AuthState;
import fr.lordmoontrix.moontrixlogin.service.MessageService;
import fr.lordmoontrix.moontrixlogin.service.TotpService;
import fr.lordmoontrix.moontrixlogin.session.SessionManager;
import fr.lordmoontrix.moontrixlogin.util.SchedulerUtil;
import java.util.Locale;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;

public final class TotpCommand implements CommandExecutor {
    private final Plugin plugin;
    private final TotpService totpService;
    private final MessageService messages;
    private final SessionManager sessionManager;

    public TotpCommand(Plugin plugin, TotpService totpService, MessageService messages, SessionManager sessionManager) {
        this.plugin = plugin;
        this.totpService = totpService;
        this.messages = messages;
        this.sessionManager = sessionManager;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player)) {
            sender.sendMessage("Only players can use this command.");
            return true;
        }
        Player player = (Player) sender;
        if (!sessionManager.get(player.getUniqueId())
            .map(s -> s.getState() == AuthState.AUTHENTICATED).orElse(false)) {
            player.sendMessage(messages.get("error.not_logged_in", "You're not logged in!"));
            return true;
        }
        if (args.length < 1) {
            player.sendMessage("Usage: /totp add|confirm|remove|code");
            return true;
        }
        String sub = args[0].toLowerCase(Locale.ROOT);
        if (sub.equals("add")) {
            if (!player.hasPermission("moontrixlogin.player.totpadd")) {
                player.sendMessage(messages.get("error.no_permission", "No permission."));
                return true;
            }
            totpService.beginSetup(player.getUniqueId()).thenAccept(secret -> {
                send(player, "TOTP secret: " + secret + " (add this to your authenticator app)");
            });
            return true;
        }
        if (sub.equals("confirm")) {
            if (!player.hasPermission("moontrixlogin.player.totpadd")) {
                player.sendMessage(messages.get("error.no_permission", "No permission."));
                return true;
            }
            if (args.length != 2) {
                player.sendMessage("Usage: /totp confirm <code>");
                return true;
            }
            int code;
            try {
                code = Integer.parseInt(args[1]);
            } catch (NumberFormatException ex) {
                player.sendMessage("Invalid code.");
                return true;
            }
            totpService.confirm(player.getUniqueId(), code).thenAccept(ok -> {
                send(player, ok ? "TOTP enabled." : "Invalid TOTP code.");
            });
            return true;
        }
        if (sub.equals("remove")) {
            if (!player.hasPermission("moontrixlogin.player.totpremove")) {
                player.sendMessage(messages.get("error.no_permission", "No permission."));
                return true;
            }
            totpService.disable(player.getUniqueId()).thenAccept(ok -> {
                send(player, "TOTP disabled.");
            });
            return true;
        }
        if (sub.equals("code")) {
            totpService.get(player.getUniqueId()).thenAccept(optional -> {
                if (optional.isPresent() && optional.get().isEnabled()) {
                    send(player, "TOTP is enabled.");
                } else {
                    send(player, "TOTP is not enabled.");
                }
            });
            return true;
        }
        player.sendMessage("Usage: /totp add|confirm|remove|code");
        return true;
    }

    private void send(Player player, String message) {
        SchedulerUtil.runAtPlayer(plugin, player, () -> player.sendMessage(message));
    }
}




