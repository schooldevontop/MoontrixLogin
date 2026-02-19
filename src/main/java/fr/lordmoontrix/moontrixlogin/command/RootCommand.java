package fr.lordmoontrix.moontrixlogin.command;

import fr.lordmoontrix.moontrixlogin.model.AuthState;
import fr.lordmoontrix.moontrixlogin.model.UserRecord;
import fr.lordmoontrix.moontrixlogin.MoontrixLogin;
import fr.lordmoontrix.moontrixlogin.service.MessageService;
import fr.lordmoontrix.moontrixlogin.session.SessionManager;
import fr.lordmoontrix.moontrixlogin.storage.UserRepository;
import fr.lordmoontrix.moontrixlogin.util.SchedulerUtil;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Optional;
import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;

public final class RootCommand implements CommandExecutor {
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
        .withZone(ZoneId.systemDefault());

    private final Plugin plugin;
    private final SessionManager sessionManager;
    private final UserRepository userRepository;
    private final MessageService messages;

    public RootCommand(Plugin plugin, SessionManager sessionManager,
                       UserRepository userRepository, MessageService messages) {
        this.plugin = plugin;
        this.sessionManager = sessionManager;
        this.userRepository = userRepository;
        this.messages = messages;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (args.length == 0) {
            sender.sendMessage("MoontrixLogin admin: /" + label + " force_login|force_logout|info|reload <player>");
            return true;
        }

        String sub = args[0].toLowerCase();
        switch (sub) {
            case "force_login":
                return handleForceLogin(sender, label, args);
            case "force_logout":
                return handleForceLogout(sender, label, args);
            case "info":
                return handleInfo(sender, label, args);
            case "reload":
                return handleReload(sender);
            default:
                sender.sendMessage("Unknown subcommand. Use /" + label + " force_login|force_logout|info|reload <player>");
                return true;
        }
    }

    private boolean handleForceLogin(CommandSender sender, String label, String[] args) {
        if (!sender.hasPermission("moontrixlogin.admin.force_login")) {
            sender.sendMessage(messages.get("error.no_permission", "No permission."));
            return true;
        }
        if (args.length != 2) {
            sender.sendMessage("Usage: /" + label + " force_login <player>");
            return true;
        }
        Player target = Bukkit.getPlayerExact(args[1]);
        if (target == null) {
            sender.sendMessage(messages.get("admin.user_not_found", "User not found."));
            return true;
        }

        String ip = target.getAddress() != null ? target.getAddress().getAddress().getHostAddress() : "unknown";
        sessionManager.markAuthenticated(target.getUniqueId(), ip);

        sender.sendMessage(messages.get("admin.force_login", "Forced login for %player%.")
            .replace("%player%", target.getName()));
        target.sendMessage(messages.get("login.success", "Login successful."));
        return true;
    }

    private boolean handleForceLogout(CommandSender sender, String label, String[] args) {
        if (!sender.hasPermission("moontrixlogin.admin.force_logout")) {
            sender.sendMessage(messages.get("error.no_permission", "No permission."));
            return true;
        }
        if (args.length != 2) {
            sender.sendMessage("Usage: /" + label + " force_logout <player>");
            return true;
        }
        Player target = Bukkit.getPlayerExact(args[1]);
        if (target == null) {
            sender.sendMessage(messages.get("admin.user_not_found", "User not found."));
            return true;
        }

        sessionManager.setState(target.getUniqueId(), AuthState.UNAUTHENTICATED);
        sessionManager.clearRememberToken(target.getUniqueId());

        sender.sendMessage(messages.get("admin.force_logout", "Forced logout for %player%.")
            .replace("%player%", target.getName()));
        target.sendMessage(messages.get("misc.logout", "You have logged out."));
        return true;
    }

    private boolean handleInfo(CommandSender sender, String label, String[] args) {
        if (!sender.hasPermission("moontrixlogin.admin.info")) {
            sender.sendMessage(messages.get("error.no_permission", "No permission."));
            return true;
        }
        if (args.length != 2) {
            sender.sendMessage("Usage: /" + label + " info <player>");
            return true;
        }

        String username = args[1];
        userRepository.findByUsername(username).thenAccept(optional -> {
            SchedulerUtil.runGlobal(plugin, () -> sendInfo(sender, username, optional));
        }).exceptionally(ex -> {
            SchedulerUtil.runGlobal(plugin, () -> sender.sendMessage(messages.get(
                "error.unexpected_error", "An unexpected error occurred."
            )));
            return null;
        });
        return true;
    }

    private void sendInfo(CommandSender sender, String username, Optional<UserRecord> optional) {
        if (!optional.isPresent()) {
            sender.sendMessage(messages.get("admin.user_not_found", "User not found."));
            return;
        }
        UserRecord record = optional.get();
        String sessionState = sessionManager.get(record.getUuid())
            .map(s -> s.getState().name())
            .orElse("UNKNOWN");

        sender.sendMessage(messages.get("admin.info_header", "Account information for %player%")
            .replace("%player%", record.getUsername()));
        sender.sendMessage(messages.get("admin.info_uuid", "UUID: %uuid%")
            .replace("%uuid%", record.getUuid().toString()));
        sender.sendMessage(messages.get("admin.info_last_ip", "Last IP Address: %ip%")
            .replace("%ip%", safe(record.getLastIp())));
        sender.sendMessage(messages.get("admin.info_last_login", "Last Login Time: %time%")
            .replace("%time%", record.getLastLogin() == null ? "never" : TIME_FORMAT.format(record.getLastLogin())));
        sender.sendMessage(messages.get("admin.info_state", "Session State: %state%")
            .replace("%state%", sessionState));
        sender.sendMessage(messages.get("admin.info_email", "Email: %email%")
            .replace("%email%", safe(record.getEmail())));
    }

    private boolean handleReload(CommandSender sender) {
        if (!sender.hasPermission("moontrixlogin.admin.reload")) {
            sender.sendMessage(messages.get("error.no_permission", "No permission."));
            return true;
        }
        sender.sendMessage(messages.get("admin.reload_start", "Reloading plugin configuration..."));
        if (!(plugin instanceof MoontrixLogin)) {
            sender.sendMessage(messages.get("error.unexpected_error", "An unexpected error occurred."));
            return true;
        }
        MoontrixLogin moontrixLogin = (MoontrixLogin) plugin;
        String error = moontrixLogin.reloadRuntime();
        if (error == null) {
            sender.sendMessage(messages.get("admin.reload_done", "Configuration reloaded."));
        } else {
            sender.sendMessage(messages.get("admin.reload_failed", "Reload failed: %reason%")
                .replace("%reason%", error));
        }
        return true;
    }

    private String safe(String value) {
        return (value == null || value.trim().isEmpty()) ? "none" : value;
    }
}



