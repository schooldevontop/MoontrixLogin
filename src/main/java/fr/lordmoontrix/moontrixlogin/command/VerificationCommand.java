package fr.lordmoontrix.moontrixlogin.command;

import fr.lordmoontrix.moontrixlogin.model.AuthState;
import fr.lordmoontrix.moontrixlogin.service.MessageService;
import fr.lordmoontrix.moontrixlogin.service.VerificationService;
import fr.lordmoontrix.moontrixlogin.session.SessionManager;
import fr.lordmoontrix.moontrixlogin.storage.UserRepository;
import java.util.concurrent.CompletableFuture;
import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;

public final class VerificationCommand implements CommandExecutor {
    private final Plugin plugin;
    private final UserRepository userRepository;
    private final VerificationService verificationService;
    private final MessageService messages;
    private final SessionManager sessionManager;

    public VerificationCommand(Plugin plugin, UserRepository userRepository,
                               VerificationService verificationService, MessageService messages,
                               SessionManager sessionManager) {
        this.plugin = plugin;
        this.userRepository = userRepository;
        this.verificationService = verificationService;
        this.messages = messages;
        this.sessionManager = sessionManager;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage("Only players can use this command.");
            return true;
        }
        if (args.length != 1) {
            player.sendMessage("Usage: /verification <code>");
            return true;
        }
        if (!player.hasPermission("moontrixlogin.player.security.verificationcode")) {
            player.sendMessage(messages.get("error.no_permission", "No permission."));
            return true;
        }
        if (!sessionManager.get(player.getUniqueId())
            .map(s -> s.getState() == AuthState.AUTHENTICATED).orElse(false)) {
            player.sendMessage(messages.get("error.not_logged_in", "You're not logged in!"));
            return true;
        }
        String code = args[0];
        verificationService.verifyAndConsume(player.getUniqueId(), code).thenCompose(recordOpt -> {
            if (recordOpt.isEmpty()) {
                return CompletableFuture.completedFuture(false);
            }
            String email = recordOpt.get().getEmail();
            return userRepository.updateEmail(player.getUniqueId(), email);
        }).thenAccept(updated -> {
            if (updated) {
                send(player, messages.get("email.changed", "Email verified and updated."));
            } else {
                send(player, messages.get("error.unexpected_error", "Unexpected error."));
            }
        });
        return true;
    }

    private void send(Player player, String message) {
        Bukkit.getScheduler().runTask(plugin, () -> player.sendMessage(message));
    }
}
