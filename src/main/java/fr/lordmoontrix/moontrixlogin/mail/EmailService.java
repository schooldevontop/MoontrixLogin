package fr.lordmoontrix.moontrixlogin.mail;

import fr.lordmoontrix.moontrixlogin.config.PluginConfig;
import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.logging.Logger;

public final class EmailService {
    private final PluginConfig.Mail config;
    private final ExecutorService executor;
    private final Logger logger;

    public EmailService(PluginConfig.Mail config, ExecutorService executor, Logger logger) {
        this.config = config;
        this.executor = executor;
        this.logger = logger;
    }

    public boolean isEnabled() {
        return config.isEnabled();
    }

    public CompletableFuture<Void> sendHtml(String to, String subject, String html) {
        return send(to, subject, html, true);
    }

    public CompletableFuture<Void> sendText(String to, String subject, String text) {
        return send(to, subject, text, false);
    }

    private CompletableFuture<Void> send(String to, String subject, String body, boolean html) {
        if (!config.isEnabled()) {
            CompletableFuture<Void> failed = new CompletableFuture<Void>();
            failed.completeExceptionally(new IllegalStateException("Mail disabled"));
            return failed;
        }
        return CompletableFuture.runAsync(() -> {
            try {
                Session session = createSession();
                MimeMessage message = new MimeMessage(session);
                message.setFrom(new InternetAddress(config.getFrom()));
                message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
                message.setSubject(subject, "UTF-8");
                if (html) {
                    message.setContent(body, "text/html; charset=UTF-8");
                } else {
                    message.setText(body, "UTF-8");
                }
                Transport.send(message);
            } catch (MessagingException ex) {
                logger.severe("Email send failed to " + maskEmail(to) + " via " + config.getHost()
                    + ":" + config.getPort() + " (" + ex.getMessage() + ")");
                throw new RuntimeException("Failed to send email", ex);
            }
        }, executor);
    }

    private Session createSession() {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.host", config.getHost());
        props.put("mail.smtp.port", Integer.toString(config.getPort()));
        if (config.isUseTls()) {
            props.put("mail.smtp.starttls.enable", "true");
        }
        if (config.isUseSsl()) {
            props.put("mail.smtp.ssl.enable", "true");
        }
        return Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(config.getUsername(), config.getPassword());
            }
        });
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


