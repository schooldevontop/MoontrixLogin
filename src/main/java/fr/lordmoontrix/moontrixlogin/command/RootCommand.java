package fr.lordmoontrix.moontrixlogin.command;

import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;

public final class RootCommand implements CommandExecutor {
    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        sender.sendMessage("MoontrixLogin: core commands are /register, /login, /logout, /changepassword, /unregister.");
        return true;
    }
}
