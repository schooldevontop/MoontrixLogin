package fr.lordmoontrix.moontrixlogin.service;

import java.io.File;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.Plugin;

public final class MessageService {
    private final FileConfiguration messages;
    private final String languageCode;

    public MessageService(Plugin plugin) {
        String configuredLanguage = plugin.getConfig().getString("language", "en");
        String normalized = normalizeLanguage(configuredLanguage);
        File selected = new File(plugin.getDataFolder(), "messages/messages_" + normalized + ".yml");
        if (!selected.exists()) {
            selected = new File(plugin.getDataFolder(), "messages/messages_en.yml");
            normalized = "en";
        }
        this.languageCode = normalized;
        this.messages = YamlConfiguration.loadConfiguration(selected);
    }

    public String get(String path, String fallback) {
        String value = messages.getString(path);
        return value == null ? fallback : value;
    }

    public String getLanguageCode() {
        return languageCode;
    }

    private String normalizeLanguage(String raw) {
        if (raw == null) {
            return "en";
        }
        String value = raw.trim().toLowerCase();
        if ("vi".equals(value)) {
            return "vi";
        }
        return "en";
    }
}


