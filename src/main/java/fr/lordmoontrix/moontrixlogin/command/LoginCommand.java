package fr.lordmoontrix.moontrixlogin.command;

import fr.lordmoontrix.moontrixlogin.model.AuthState;
import fr.lordmoontrix.moontrixlogin.security.AntiBotService;
import fr.lordmoontrix.moontrixlogin.security.DeviceFingerprintService;
import fr.lordmoontrix.moontrixlogin.service.AuthResult;
import fr.lordmoontrix.moontrixlogin.service.AuthService;
import fr.lordmoontrix.moontrixlogin.service.CaptchaService;
import fr.lordmoontrix.moontrixlogin.service.MessageService;
import fr.lordmoontrix.moontrixlogin.service.TotpService;
import fr.lordmoontrix.moontrixlogin.session.JwtSessionTokenService;
import fr.lordmoontrix.moontrixlogin.session.SessionManager;
import fr.lordmoontrix.moontrixlogin.util.SchedulerUtil;
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
    private final DeviceFingerprintService fingerprintService;
    private final JwtSessionTokenService jwtSessionTokenService;
    private final int ipPrefixSegments;
    private final boolean rememberMeEnabled;

    public LoginCommand(Plugin plugin, AuthService authService, SessionManager sessionManager,
                        TotpService totpService, CaptchaService captchaService,
                        AntiBotService antiBotService, MessageService messages,
                        DeviceFingerprintService fingerprintService,
                        JwtSessionTokenService jwtSessionTokenService,
                        int ipPrefixSegments,
                        boolean rememberMeEnabled) {
        this.plugin = plugin;
        this.authService = authService;
        this.sessionManager = sessionManager;
        this.totpService = totpService;
        this.captchaService = captchaService;
        this.antiBotService = antiBotService;
        this.messages = messages;
        this.fingerprintService = fingerprintService;
        this.jwtSessionTokenService = jwtSessionTokenService;
        this.ipPrefixSegments = ipPrefixSegments;
        this.rememberMeEnabled = rememberMeEnabled;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player)) {
            sender.sendMessage("Only players can use this command.");
            return true;
        }
        Player player = (Player) sender;
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
        if (args.length < 1 || args.length > 3) {
            player.sendMessage(messages.get("login.command_usage", "Usage: /login <password> [totp] [remember]"));
            return true;
        }
        String ip = player.getAddress() != null ? player.getAddress().getAddress().getHostAddress() : "unknown";
        String fingerprint = fingerprintService.fingerprint(player, ip, ipPrefixSegments);
        boolean rememberMe = rememberMeEnabled && hasRememberFlag(args);
        antiBotService.recordLoginAttempt(ip, player.getName());
        AntiBotService.Decision decision = antiBotService.evaluate(ip, fingerprint);
        if (decision.getType() == AntiBotService.DecisionType.CAPTCHA) {
            issueCaptcha(player);
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
            SchedulerUtil.runAtPlayerLater(plugin, player, () -> processLogin(player, args, ip, fingerprint, rememberMe),
                decision.getSeconds() * 20L);
            return true;
        }
        processLogin(player, args, ip, fingerprint, rememberMe);
        return true;
    }

    private void processLogin(Player player, String[] args, String ip, String fingerprint, boolean rememberMe) {
        if (!player.isOnline()) {
            return;
        }
        authService.verifyPassword(player.getUniqueId(), player.getName(), args[0], ip, fingerprint)
            .thenCompose(result -> {
                if (!result.isSuccess()) {
                    antiBotService.recordFingerprintFailure(fingerprint);
                    if (result.getCode() == AuthResult.Code.LOCKED) {
                        antiBotService.markBruteForce(ip);
                    }
                    return java.util.concurrent.CompletableFuture.completedFuture(result);
                }
                antiBotService.clearFingerprintFailure(fingerprint);
                return totpService.get(player.getUniqueId()).thenCompose(totpOpt -> {
                    if (totpOpt.isPresent() && totpOpt.get().isEnabled()) {
                        String totpArg = findTotpArg(args);
                        if (totpArg == null) {
                            return java.util.concurrent.CompletableFuture.completedFuture(
                                AuthResult.fail("TOTP required. Usage: /login <password> <totp>"));
                        }
                        int code;
                        try {
                            code = Integer.parseInt(totpArg);
                        } catch (NumberFormatException ex) {
                            return java.util.concurrent.CompletableFuture.completedFuture(
                                AuthResult.fail("Invalid TOTP code."));
                        }
                        return totpService.validate(player.getUniqueId(), code)
                            .thenCompose(ok -> ok
                                ? completeWithRemember(player, ip, fingerprint, rememberMe)
                                : java.util.concurrent.CompletableFuture.completedFuture(
                                    AuthResult.fail("Invalid TOTP code.")));
                    }
                    return completeWithRemember(player, ip, fingerprint, rememberMe);
                });
            })
            .thenAccept(result -> sendResult(player, result))
            .exceptionally(ex -> {
                plugin.getLogger().log(Level.SEVERE, "Login failed", ex);
                sendError(player);
                return null;
            });
    }

    private java.util.concurrent.CompletableFuture<AuthResult> completeWithRemember(
        Player player, String ip, String fingerprint, boolean rememberMe
    ) {
        return authService.completeLogin(player.getUniqueId(), ip, fingerprint).thenApply(result -> {
            if (rememberMe && result.isSuccess() && jwtSessionTokenService != null) {
                String ipPrefix = fingerprintService.normalizeIpPrefix(ip, ipPrefixSegments);
                String token = jwtSessionTokenService.issueRememberToken(player.getUniqueId(), fingerprint, ipPrefix);
                sessionManager.setRememberToken(player.getUniqueId(), token);
                return AuthResult.ok(result.getMessage() + " Remember-me enabled for this device.");
            }
            return result;
        });
    }

    private void issueCaptcha(Player player) {
        String code = captchaService.create(player.getUniqueId());
        String template = messages.get("captcha.message", "Captcha: %code%");
        player.sendMessage(messages.get("captcha.required", "Captcha required before login."));
        player.sendMessage(template.replace("%code%", code));
    }

    private boolean hasRememberFlag(String[] args) {
        for (String arg : args) {
            String value = arg.toLowerCase(java.util.Locale.ROOT);
            if ("remember".equals(value) || "--remember".equals(value) || "-r".equals(value)) {
                return true;
            }
        }
        return false;
    }

    private String findTotpArg(String[] args) {
        for (int i = 1; i < args.length; i++) {
            String value = args[i].toLowerCase(java.util.Locale.ROOT);
            if ("remember".equals(value) || "--remember".equals(value) || "-r".equals(value)) {
                continue;
            }
            return args[i];
        }
        return null;
    }

    private void sendResult(Player player, AuthResult result) {
        SchedulerUtil.runAtPlayer(plugin, player, () -> player.sendMessage(result.getMessage()));
    }

    private void sendError(Player player) {
        SchedulerUtil.runAtPlayer(plugin, player, () -> player.sendMessage("An unexpected error occurred."));
    }
}




