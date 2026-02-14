package fr.lordmoontrix.moontrixlogin.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.logging.Logger;
import org.bukkit.Bukkit;

public final class ServerVersionRuntimeCheck {
    private static final Version MIN_SUPPORTED = new Version(1, 8, 0);
    private static final Version LEGACY_WARN_MAX = new Version(1, 12, 2);
    private static final Version RECOMMENDED_MIN = new Version(1, 13, 0);
    private static final Version TESTED_MAX = new Version(1, 21, 11);
    private static final Pattern VERSION_PATTERN = Pattern.compile("(\\d+)\\.(\\d+)(?:\\.(\\d+))?");

    private ServerVersionRuntimeCheck() {
    }

    public static void logCompatibility(Logger logger) {
        String bukkitVersion = Bukkit.getBukkitVersion();
        Version detected = parseVersion(bukkitVersion);
        if (detected == null) {
            logger.warning("[Compatibility] Unable to parse server version: " + bukkitVersion);
            logger.warning("[Compatibility] Supported range is 1.8.0 to 1.21.11.");
            return;
        }

        logger.info("[Compatibility] Detected server version: " + detected + " (" + bukkitVersion + ")");

        if (detected.compareTo(MIN_SUPPORTED) < 0) {
            logger.severe("[Compatibility] Server is below minimum supported version 1.8.0. Plugin may not work.");
            return;
        }

        if (detected.compareTo(LEGACY_WARN_MAX) <= 0) {
            logger.warning("[Compatibility] Legacy server detected (" + detected + ").");
            logger.warning("[Compatibility] Recommended runtime range is " + RECOMMENDED_MIN + " to " + TESTED_MAX + ".");
            return;
        }

        if (detected.compareTo(TESTED_MAX) > 0) {
            logger.warning("[Compatibility] Server version " + detected + " is newer than tested max " + TESTED_MAX + ".");
            logger.warning("[Compatibility] Plugin should still run, but full compatibility is not guaranteed yet.");
            return;
        }

        logger.info("[Compatibility] Server version is within tested support range.");
    }

    private static Version parseVersion(String value) {
        if (value == null) {
            return null;
        }
        Matcher matcher = VERSION_PATTERN.matcher(value);
        if (!matcher.find()) {
            return null;
        }
        int major = Integer.parseInt(matcher.group(1));
        int minor = Integer.parseInt(matcher.group(2));
        int patch = matcher.group(3) == null ? 0 : Integer.parseInt(matcher.group(3));
        return new Version(major, minor, patch);
    }

    private static final class Version implements Comparable<Version> {
        private final int major;
        private final int minor;
        private final int patch;

        private Version(int major, int minor, int patch) {
            this.major = major;
            this.minor = minor;
            this.patch = patch;
        }

        @Override
        public int compareTo(Version other) {
            if (major != other.major) {
                return Integer.compare(major, other.major);
            }
            if (minor != other.minor) {
                return Integer.compare(minor, other.minor);
            }
            return Integer.compare(patch, other.patch);
        }

        @Override
        public String toString() {
            return major + "." + minor + "." + patch;
        }
    }
}
