package fr.lordmoontrix.moontrixlogin.util;

import java.lang.reflect.Method;
import java.util.Locale;
import java.util.logging.Logger;
import org.bukkit.Bukkit;

public final class PlatformRuntimeCheck {
    private PlatformRuntimeCheck() {
    }

    public static void logPlatform(Logger logger) {
        String detected = detectPlatform();
        String bukkitName = safe(Bukkit.getName());
        String bukkitVersion = safe(Bukkit.getVersion());

        logger.info("[Platform] Detected platform: " + detected + " (" + bukkitName + ")");
        logger.info("[Platform] Server runtime: " + bukkitVersion);
        logger.info("[Platform] Target support: Bukkit, Spigot, Paper, Purpur, Pufferfish, Folia (1.8 - 1.21.11).");
    }

    private static String detectPlatform() {
        if (hasMethod(Bukkit.getServer().getClass(), "getGlobalRegionScheduler")) {
            return "Folia-compatible";
        }

        String name = (safe(Bukkit.getName()) + " " + safe(Bukkit.getVersion())).toLowerCase(Locale.ROOT);
        if (name.contains("pufferfish")) {
            return "Pufferfish";
        }
        if (name.contains("purpur")) {
            return "Purpur";
        }
        if (name.contains("paper")) {
            return "Paper";
        }
        if (name.contains("spigot")) {
            return "Spigot";
        }
        if (name.contains("craftbukkit") || name.contains("bukkit")) {
            return "Bukkit/CraftBukkit";
        }
        return "Unknown Bukkit-API platform";
    }

    private static boolean hasMethod(Class<?> type, String name, Class<?>... params) {
        try {
            Method method = type.getMethod(name, params);
            return method != null;
        } catch (NoSuchMethodException ex) {
            return false;
        }
    }

    private static String safe(String value) {
        return value == null ? "unknown" : value;
    }
}


