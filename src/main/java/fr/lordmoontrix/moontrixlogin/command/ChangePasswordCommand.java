package fr.lordmoontrix.moontrixlogin.command;

import fr.lordmoontrix.moontrixlogin.model.AuthState;
import fr.lordmoontrix.moontrixlogin.service.AuthResult;
import fr.lordmoontrix.moontrixlogin.service.AuthService;
import fr.lordmoontrix.moontrixlogin.session.SessionManager;
import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import java.util.logging.Level;

public final class ChangePasswordCommand implements CommandExecutor {
    private final Plugin plugin;
    private final AuthService authService;
    private final SessionManager sessionManager;

    public ChangePasswordCommand(Plugin plugin, AuthService authService, SessionManager sessionManager) {
        this.plugin = plugin;
        this.authService = authService;
        this.sessionManager = sessionManager;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage("Only players can use this command.");
            return true;
        }
        if (!player.hasPermission("moontrixlogin.player.changepassword")) {
            player.sendMessage("No permission.");
            return true;
        }
        if (!sessionManager.get(player.getUniqueId())
            .map(session -> session.getState() == AuthState.AUTHENTICATED).orElse(false)) {
            player.sendMessage("You must login first.");
            return true;
        }
        if (args.length != 2) {
            player.sendMessage("Usage: /changepassword <oldPassword> <newPassword>");
            return true;
        }
        authService.changePassword(player.getUniqueId(), args[0], args[1])
            .thenAccept(result -> sendResult(player, result))
            .exceptionally(ex -> {
                plugin.getLogger().log(Level.SEVERE, "Change password failed", ex);
                sendError(player);
                return null;
            });
        return true;
    }

    private void sendResult(Player player, AuthResult result) {
        Bukkit.getScheduler().runTask(plugin, () -> player.sendMessage(result.getMessage()));
    }

    private void sendError(Player player) {
        Bukkit.getScheduler().runTask(plugin, () -> player.sendMessage("An unexpected error occurred."));
    }
}
