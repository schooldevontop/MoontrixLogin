package fr.lordmoontrix.moontrixlogin.service;

import java.io.File;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.Plugin;

public final class MessageService {
    private final FileConfiguration messages;

    public MessageService(Plugin plugin) {
        File file = new File(plugin.getDataFolder(), "messages/messages_en.yml");
        this.messages = YamlConfiguration.loadConfiguration(file);
    }

    public String get(String path, String fallback) {
        String value = messages.getString(path);
        return value == null ? fallback : value;
    }
}
