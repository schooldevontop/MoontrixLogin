package fr.lordmoontrix.moontrixlogin.command;

import fr.lordmoontrix.moontrixlogin.crypto.PasswordHasher;
import fr.lordmoontrix.moontrixlogin.mail.EmailRecoverLimiter;
import fr.lordmoontrix.moontrixlogin.mail.EmailRateLimiter;
import fr.lordmoontrix.moontrixlogin.mail.EmailService;
import fr.lordmoontrix.moontrixlogin.model.AuthState;
import fr.lordmoontrix.moontrixlogin.security.PasswordPolicy;
import fr.lordmoontrix.moontrixlogin.service.MessageService;
import fr.lordmoontrix.moontrixlogin.service.PasswordResetService;
import fr.lordmoontrix.moontrixlogin.service.VerificationService;
import fr.lordmoontrix.moontrixlogin.session.SessionManager;
import fr.lordmoontrix.moontrixlogin.storage.UserRepository;
import fr.lordmoontrix.moontrixlogin.util.SchedulerUtil;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;

public final class EmailCommand implements CommandExecutor {
    private final Plugin plugin;
    private final UserRepository userRepository;
    private final VerificationService verificationService;
    private final PasswordResetService passwordResetService;
    private final MessageService messages;
    private final SessionManager sessionManager;
    private final EmailService emailService;
    private final PasswordHasher passwordHasher;
    private final PasswordPolicy passwordPolicy;
    private final EmailRateLimiter verifyLimiter;
    private final EmailRateLimiter resetLimiter;
    private final EmailRecoverLimiter recoverLimiter;

    public EmailCommand(Plugin plugin, UserRepository userRepository,
                        VerificationService verificationService, PasswordResetService passwordResetService,
                        MessageService messages, SessionManager sessionManager, EmailService emailService,
                        PasswordHasher passwordHasher, PasswordPolicy passwordPolicy,
                        EmailRateLimiter verifyLimiter,
                        EmailRateLimiter resetLimiter, EmailRecoverLimiter recoverLimiter) {
        this.plugin = plugin;
        this.userRepository = userRepository;
        this.verificationService = verificationService;
        this.passwordResetService = passwordResetService;
        this.messages = messages;
        this.sessionManager = sessionManager;
        this.emailService = emailService;
        this.passwordHasher = passwordHasher;
        this.passwordPolicy = passwordPolicy;
        this.verifyLimiter = verifyLimiter;
        this.resetLimiter = resetLimiter;
        this.recoverLimiter = recoverLimiter;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player)) {
            sender.sendMessage("Only players can use this command.");
            return true;
        }
        Player player = (Player) sender;
        if (args.length < 1) {
            player.sendMessage("Usage: /email show|add|change|recover");
            return true;
        }
        String sub = args[0].toLowerCase(Locale.ROOT);
        if (sub.equals("show")) {
            if (!isLoggedIn(player)) {
                player.sendMessage(messages.get("error.not_logged_in", "You're not logged in!"));
                return true;
            }
            if (!player.hasPermission("moontrixlogin.player.email.see")) {
                player.sendMessage(messages.get("error.no_permission", "No permission."));
                return true;
            }
            handleShow(player);
            return true;
        }
        if (sub.equals("add") || sub.equals("change")) {
            if (!isLoggedIn(player)) {
                player.sendMessage(messages.get("error.not_logged_in", "You're not logged in!"));
                return true;
            }
            String perm = sub.equals("add") ? "moontrixlogin.player.email.add" : "moontrixlogin.player.email.change";
            if (!player.hasPermission(perm)) {
                player.sendMessage(messages.get("error.no_permission", "No permission."));
                return true;
            }
            if (args.length != 2) {
                player.sendMessage("Usage: /email " + sub + " <email>");
                return true;
            }
            handleAddOrChange(player, args[1]);
            return true;
        }
        if (sub.equals("recover")) {
            if (!player.hasPermission("moontrixlogin.player.email.recover")) {
                player.sendMessage(messages.get("error.no_permission", "No permission."));
                return true;
            }
            if (args.length != 2) {
                player.sendMessage("Usage: /email recover <email>");
                return true;
            }
            handleRecover(player, args[1]);
            return true;
        }
        if (sub.equals("setpassword")) {
            if (args.length != 3) {
                player.sendMessage("Usage: /email setpassword <code> <newPassword>");
                return true;
            }
            EmailRateLimiter.Result limitResult = resetLimiter.tryAcquire(player.getUniqueId().toString());
            if (!limitResult.isAllowed()) {
                String msg = messages.get(
                    "email.reset_rate_limited",
                    "Too many reset attempts. Try again in %seconds% seconds."
                ).replace("%seconds%", Long.toString(limitResult.getRetryAfterSeconds()));
                send(player, msg);
                return true;
            }
            handleSetPassword(player, args[1], args[2]);
            return true;
        }
        player.sendMessage("Usage: /email show|add|change|recover|setpassword");
        return true;
    }

    private void handleShow(Player player) {
        userRepository.findByUuid(player.getUniqueId()).thenAccept(optional -> {
            String email = optional.map(r -> Optional.ofNullable(r.getEmail()).orElse("none")).orElse("none");
            send(player, "Your email: " + email);
        });
    }

    private void handleAddOrChange(Player player, String email) {
        if (!emailService.isEnabled()) {
            send(player, messages.get("email.mail_disabled", "Email service is disabled."));
            return;
        }
        EmailRateLimiter.Result limitResult = verifyLimiter.tryAcquire(player.getUniqueId().toString());
        if (!limitResult.isAllowed()) {
            String msg = messages.get(
                "email.verify_rate_limited",
                "Too many verification requests. Try again in %seconds% seconds."
            ).replace("%seconds%", Long.toString(limitResult.getRetryAfterSeconds()));
            send(player, msg);
            return;
        }
        UUID uuid = player.getUniqueId();
        verificationService.createCode(uuid, email).thenAccept(code -> {
            String subject = "MoontrixLogin email verification";
            String body = renderTemplate(
                "templates/email_verify.html",
                templateValues(code, player.getName(), email),
                "Your verification code: " + code
            );
            emailService.sendHtml(email, subject, body)
                .thenRun(() -> send(player, messages.get("email.added",
                    "Verification code sent. Use /verification <code>.")))
                .exceptionally(ex -> {
                    plugin.getLogger().severe("Email verification send failed for " + player.getName()
                        + " (" + maskEmail(email) + "): " + ex.getMessage());
                    send(player, messages.get("error.unexpected_error", "Unexpected error."));
                    return null;
                });
        });
    }

    private void handleRecover(Player player, String email) {
        if (!emailService.isEnabled()) {
            send(player, messages.get("email.mail_disabled", "Email service is disabled."));
            return;
        }
        fr.lordmoontrix.moontrixlogin.mail.EmailRateLimiter.Result limitResult =
            recoverLimiter.tryAcquire(player.getUniqueId(), email);
        if (!limitResult.isAllowed()) {
            String msg = messages.get(
                "email.recover_rate_limited",
                "Too many recovery requests. Try again in %seconds% seconds."
            ).replace("%seconds%", Long.toString(limitResult.getRetryAfterSeconds()));
            send(player, msg);
            return;
        }
        userRepository.findByUuid(player.getUniqueId()).thenCompose(optional -> {
            if (!optional.isPresent() || optional.get().getEmail() == null) {
                return CompletableFuture.completedFuture(false);
            }
            if (!optional.get().getEmail().equalsIgnoreCase(email)) {
                return CompletableFuture.completedFuture(false);
            }
            return passwordResetService.create(player.getUniqueId(), email).thenCompose(code -> {
                String subject = "MoontrixLogin password reset";
                String body = renderTemplate(
                    "templates/email_recover.html",
                    templateValues(code, player.getName(), email),
                    "Your reset code: " + code
                );
                return emailService.sendHtml(email, subject, body).thenApply(v -> true);
            });
        }).thenAccept(ok -> {
            if (ok) {
                send(player, messages.get("email.recover", "Recovery code sent. Use /email setpassword <code> <newPassword>."));
            } else {
                send(player, messages.get("error.unregistered_user", "User not registered."));
            }
        }).exceptionally(ex -> {
            plugin.getLogger().severe("Password recovery failed for " + player.getName()
                + " (" + maskEmail(email) + "): " + ex.getMessage());
            send(player, messages.get("error.unexpected_error", "Unexpected error."));
            return null;
        });
    }

    private void handleSetPassword(Player player, String code, String newPassword) {
        PasswordPolicy.Result policyResult = passwordPolicy.validate(newPassword);
        if (policyResult != PasswordPolicy.Result.OK) {
            send(player, passwordPolicyMessage(policyResult));
            return;
        }
        passwordResetService.consumeByCode(code).thenCompose(optional -> {
            if (!optional.isPresent()) {
                return CompletableFuture.completedFuture(false);
            }
            if (!optional.get().getUuid().equals(player.getUniqueId())) {
                return CompletableFuture.completedFuture(false);
            }
            String hash = passwordHasher.hash(newPassword.toCharArray());
            return userRepository.updatePassword(player.getUniqueId(), hash);
        }).thenAccept(ok -> {
            if (ok) {
                send(player, messages.get("email.reset_success", "Password reset successfully."));
            } else {
                send(player, messages.get("email.reset_failed", "Invalid or expired code."));
            }
        });
    }

    private void send(Player player, String message) {
        SchedulerUtil.runAtPlayer(plugin, player, () -> player.sendMessage(message));
    }

    private boolean isLoggedIn(Player player) {
        return sessionManager.get(player.getUniqueId())
            .map(s -> s.getState() == AuthState.AUTHENTICATED).orElse(false);
    }

    private String renderTemplate(String resourcePath, Map<String, String> values, String fallback) {
        String template = loadResource(resourcePath);
        if (template == null) {
            return fallback;
        }
        String rendered = template;
        for (Map.Entry<String, String> entry : values.entrySet()) {
            rendered = rendered.replace("{{" + entry.getKey() + "}}", entry.getValue());
        }
        return rendered;
    }

    private Map<String, String> templateValues(String code, String playerName, String email) {
        Map<String, String> values = new HashMap<String, String>();
        values.put("CODE", code);
        values.put("PLAYER", playerName);
        values.put("EMAIL", email);
        return values;
    }

    private String loadResource(String resourcePath) {
        try (InputStream input = plugin.getResource(resourcePath)) {
            if (input == null) {
                return null;
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append('\n');
                }
                return sb.toString();
            }
        } catch (Exception ex) {
            plugin.getLogger().warning("Failed to load email template " + resourcePath + ": " + ex.getMessage());
            return null;
        }
    }

    private String passwordPolicyMessage(PasswordPolicy.Result result) {
        switch (result) {
            case TOO_SHORT:
            case TOO_LONG:
                return messages.get("password.wrong_length", "Password length is invalid.");
            case BLACKLISTED:
                return messages.get("password.blacklisted", "Password is not allowed.");
            case MISSING_REQUIRED:
            default:
                return messages.get("password.unsafe_password", "Password does not meet security requirements.");
        }
    }

    private String maskEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            return "unknown";
        }
        int at = email.indexOf('@');
        if (at <= 1) {
            return "***";
        }
        String name = email.substring(0, at);
        String domain = email.substring(at);
        String prefix = name.substring(0, Math.min(2, name.length()));
        return prefix + "***" + domain;
    }
}




