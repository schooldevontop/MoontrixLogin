package fr.lordmoontrix.moontrixlogin.command;

import fr.lordmoontrix.moontrixlogin.model.AuthState;
import fr.lordmoontrix.moontrixlogin.security.AntiBotService;
import fr.lordmoontrix.moontrixlogin.service.AuthResult;
import fr.lordmoontrix.moontrixlogin.service.AuthService;
import fr.lordmoontrix.moontrixlogin.service.CaptchaService;
import fr.lordmoontrix.moontrixlogin.service.MessageService;
import fr.lordmoontrix.moontrixlogin.service.TotpService;
import fr.lordmoontrix.moontrixlogin.session.SessionManager;
import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import java.util.logging.Level;

public final class LoginCommand implements CommandExecutor {
    private final Plugin plugin;
    private final AuthService authService;
    private final SessionManager sessionManager;
    private final TotpService totpService;
    private final CaptchaService captchaService;
    private final AntiBotService antiBotService;
    private final MessageService messages;

    public LoginCommand(Plugin plugin, AuthService authService, SessionManager sessionManager,
                        TotpService totpService, CaptchaService captchaService,
                        AntiBotService antiBotService, MessageService messages) {
        this.plugin = plugin;
        this.authService = authService;
        this.sessionManager = sessionManager;
        this.totpService = totpService;
        this.captchaService = captchaService;
        this.antiBotService = antiBotService;
        this.messages = messages;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage("Only players can use this command.");
            return true;
        }
        if (!player.hasPermission("moontrixlogin.player.login")) {
            player.sendMessage("No permission.");
            return true;
        }
        if (sessionManager.get(player.getUniqueId())
            .map(session -> session.getState() == AuthState.AUTHENTICATED).orElse(false)) {
            player.sendMessage("You are already logged in.");
            return true;
        }
        if (captchaService.hasPending(player.getUniqueId())) {
            player.sendMessage("Please complete captcha first using /captcha <code>.");
            return true;
        }
        if (args.length < 1 || args.length > 2) {
            player.sendMessage("Usage: /login <password> [totp]");
            return true;
        }
        String ip = player.getAddress() != null ? player.getAddress().getAddress().getHostAddress() : "unknown";
        antiBotService.recordLoginAttempt(ip, player.getName());
        AntiBotService.Decision decision = antiBotService.evaluate(ip);
        if (decision.getType() == AntiBotService.DecisionType.SHADOW_BAN) {
            player.sendMessage(messages.get("error.shadow_ban", "Login temporarily restricted."));
            return true;
        }
        if (decision.getType() == AntiBotService.DecisionType.LOCK) {
            player.sendMessage(messages.get("error.login_wait", "Too many attempts. Please wait."));
            return true;
        }
        if (decision.getType() == AntiBotService.DecisionType.DELAY && decision.getSeconds() > 0) {
            Bukkit.getScheduler().runTaskLater(plugin, () -> {
                processLogin(player, args, ip);
            }, decision.getSeconds() * 20L);
            return true;
        }
        processLogin(player, args, ip);
        return true;
    }

    private void processLogin(Player player, String[] args, String ip) {
        if (!player.isOnline()) {
            return;
        }
        authService.verifyPassword(player.getUniqueId(), player.getName(), args[0], ip)
            .thenCompose(result -> {
                if (!result.isSuccess()) {
                    if (result.getCode() == AuthResult.Code.LOCKED) {
                        antiBotService.markBruteForce(ip);
                    }
                    return java.util.concurrent.CompletableFuture.completedFuture(result);
                }
                return totpService.get(player.getUniqueId()).thenCompose(totpOpt -> {
                    if (totpOpt.isPresent() && totpOpt.get().isEnabled()) {
                        if (args.length < 2) {
                            return java.util.concurrent.CompletableFuture.completedFuture(
                                AuthResult.fail("TOTP required. Usage: /login <password> <totp>"));
                        }
                        int code;
                        try {
                            code = Integer.parseInt(args[1]);
                        } catch (NumberFormatException ex) {
                            return java.util.concurrent.CompletableFuture.completedFuture(
                                AuthResult.fail("Invalid TOTP code."));
                        }
                        return totpService.validate(player.getUniqueId(), code)
                            .thenCompose(ok -> ok
                                ? authService.completeLogin(player.getUniqueId(), ip)
                                : java.util.concurrent.CompletableFuture.completedFuture(
                                    AuthResult.fail("Invalid TOTP code.")));
                    }
                    return authService.completeLogin(player.getUniqueId(), ip);
                });
            })
            .thenAccept(result -> sendResult(player, result))
            .exceptionally(ex -> {
                plugin.getLogger().log(Level.SEVERE, "Login failed", ex);
                sendError(player);
                return null;
            });
    }

    private void sendResult(Player player, AuthResult result) {
        Bukkit.getScheduler().runTask(plugin, () -> player.sendMessage(result.getMessage()));
    }

    private void sendError(Player player) {
        Bukkit.getScheduler().runTask(plugin, () -> player.sendMessage("An unexpected error occurred."));
    }
}
