package fr.lordmoontrix.moontrixlogin.command;

import fr.lordmoontrix.moontrixlogin.model.AuthState;
import fr.lordmoontrix.moontrixlogin.service.AuthResult;
import fr.lordmoontrix.moontrixlogin.service.AuthService;
import fr.lordmoontrix.moontrixlogin.service.CaptchaService;
import fr.lordmoontrix.moontrixlogin.service.MessageService;
import fr.lordmoontrix.moontrixlogin.session.SessionManager;
import fr.lordmoontrix.moontrixlogin.security.AntiBotService;
import fr.lordmoontrix.moontrixlogin.security.DeviceFingerprintService;
import fr.lordmoontrix.moontrixlogin.util.SchedulerUtil;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import java.util.logging.Level;

public final class RegisterCommand implements CommandExecutor {
    private final Plugin plugin;
    private final AuthService authService;
    private final SessionManager sessionManager;
    private final CaptchaService captchaService;
    private final AntiBotService antiBotService;
    private final MessageService messages;
    private final boolean registrationEnabled;
    private final boolean requireConfirmation;
    private final DeviceFingerprintService fingerprintService;
    private final int ipPrefixSegments;

    public RegisterCommand(Plugin plugin, AuthService authService, SessionManager sessionManager,
                           CaptchaService captchaService, AntiBotService antiBotService,
                           MessageService messages, boolean registrationEnabled,
                           boolean requireConfirmation,
                           DeviceFingerprintService fingerprintService,
                           int ipPrefixSegments) {
        this.plugin = plugin;
        this.authService = authService;
        this.sessionManager = sessionManager;
        this.captchaService = captchaService;
        this.antiBotService = antiBotService;
        this.messages = messages;
        this.registrationEnabled = registrationEnabled;
        this.requireConfirmation = requireConfirmation;
        this.fingerprintService = fingerprintService;
        this.ipPrefixSegments = ipPrefixSegments;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player)) {
            sender.sendMessage("Only players can use this command.");
            return true;
        }
        Player player = (Player) sender;
        if (!player.hasPermission("moontrixlogin.player.register")) {
            player.sendMessage("No permission.");
            return true;
        }
        if (!registrationEnabled) {
            player.sendMessage(messages.get("registration.disabled", "Registration is disabled."));
            return true;
        }
        if (sessionManager.get(player.getUniqueId())
            .map(session -> session.getState() == AuthState.AUTHENTICATED).orElse(false)) {
            player.sendMessage("You are already registered and logged in.");
            return true;
        }
        if (captchaService.hasPending(player.getUniqueId())) {
            player.sendMessage("Please complete captcha first using /captcha <code>.");
            return true;
        }
        if (args.length < 1 || args.length > 2) {
            player.sendMessage("Usage: /register <password> [verifyPassword]");
            return true;
        }
        if (requireConfirmation && args.length != 2) {
            player.sendMessage("Usage: /register <password> <verifyPassword>");
            return true;
        }
        if (args.length == 2 && !args[0].equals(args[1])) {
            player.sendMessage("Passwords do not match.");
            return true;
        }
        String ip = player.getAddress() != null ? player.getAddress().getAddress().getHostAddress() : "unknown";
        String fingerprint = fingerprintService.fingerprint(player, ip, ipPrefixSegments);
        antiBotService.recordLoginAttempt(ip, player.getName());
        AntiBotService.Decision decision = antiBotService.evaluate(ip, fingerprint);
        if (decision.getType() == AntiBotService.DecisionType.CAPTCHA) {
            String code = captchaService.create(player.getUniqueId());
            String template = messages.get("captcha.message", "Captcha: %code%");
            player.sendMessage(messages.get("captcha.required", "Captcha required before register."));
            player.sendMessage(template.replace("%code%", code));
            return true;
        }
        if (decision.getType() == AntiBotService.DecisionType.SHADOW_BAN) {
            player.sendMessage(messages.get("error.shadow_ban", "Login temporarily restricted."));
            return true;
        }
        if (decision.getType() == AntiBotService.DecisionType.LOCK) {
            player.sendMessage(messages.get("error.login_wait", "Too many attempts. Please wait."));
            return true;
        }
        if (decision.getType() == AntiBotService.DecisionType.DELAY && decision.getSeconds() > 0) {
            SchedulerUtil.runAtPlayerLater(plugin, player, () -> processRegister(player, args[0], ip),
                decision.getSeconds() * 20L);
            return true;
        }
        processRegister(player, args[0], ip);
        return true;
    }

    private void processRegister(Player player, String password, String ip) {
        if (!player.isOnline()) {
            return;
        }
        authService.register(player.getUniqueId(), player.getName(), password, ip)
            .thenAccept(result -> sendResult(player, result))
            .exceptionally(ex -> {
                plugin.getLogger().log(Level.SEVERE, "Registration failed", ex);
                sendError(player);
                return null;
            });
    }

    private void sendResult(Player player, AuthResult result) {
        SchedulerUtil.runAtPlayer(plugin, player, () -> player.sendMessage(result.getMessage()));
    }

    private void sendError(Player player) {
        SchedulerUtil.runAtPlayer(plugin, player, () -> player.sendMessage("An unexpected error occurred."));
    }
}




