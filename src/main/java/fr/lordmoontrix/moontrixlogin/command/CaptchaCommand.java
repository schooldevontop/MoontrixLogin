package fr.lordmoontrix.moontrixlogin.command;

import fr.lordmoontrix.moontrixlogin.service.CaptchaService;
import fr.lordmoontrix.moontrixlogin.service.MessageService;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

public final class CaptchaCommand implements CommandExecutor {
    private final MessageService messages;
    private final CaptchaService captchaService;

    public CaptchaCommand(MessageService messages, CaptchaService captchaService) {
        this.messages = messages;
        this.captchaService = captchaService;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player)) {
            sender.sendMessage("Only players can use this command.");
            return true;
        }
        Player player = (Player) sender;
        if (!player.hasPermission("moontrixlogin.player.captcha")) {
            player.sendMessage(messages.get("error.no_permission", "No permission."));
            return true;
        }
        if (args.length != 1) {
            player.sendMessage("Usage: /captcha <code>");
            return true;
        }
        if (!captchaService.hasPending(player.getUniqueId())) {
            player.sendMessage(messages.get("captcha.none", "No captcha required."));
            return true;
        }
        boolean ok = captchaService.verify(player.getUniqueId(), args[0]);
        player.sendMessage(ok
            ? messages.get("captcha.success", "Captcha completed.")
            : messages.get("captcha.failed", "Invalid captcha."));
        return true;
    }
}




