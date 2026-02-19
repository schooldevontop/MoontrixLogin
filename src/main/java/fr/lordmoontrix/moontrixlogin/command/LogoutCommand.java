package fr.lordmoontrix.moontrixlogin.command;

import fr.lordmoontrix.moontrixlogin.model.AuthState;
import fr.lordmoontrix.moontrixlogin.service.MessageService;
import fr.lordmoontrix.moontrixlogin.session.SessionManager;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

public final class LogoutCommand implements CommandExecutor {
    private final SessionManager sessionManager;
    private final MessageService messages;

    public LogoutCommand(SessionManager sessionManager, MessageService messages) {
        this.sessionManager = sessionManager;
        this.messages = messages;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player)) {
            sender.sendMessage("Only players can use this command.");
            return true;
        }
        Player player = (Player) sender;
        if (!player.hasPermission("moontrixlogin.player.logout")) {
            player.sendMessage("No permission.");
            return true;
        }
        sessionManager.clearRememberToken(player.getUniqueId());
        sessionManager.setState(player.getUniqueId(), AuthState.UNAUTHENTICATED);
        player.sendMessage(messages.get("misc.logout", "Logged out."));
        return true;
    }
}




