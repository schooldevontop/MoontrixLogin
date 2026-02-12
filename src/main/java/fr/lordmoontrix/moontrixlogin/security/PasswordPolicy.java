package fr.lordmoontrix.moontrixlogin.security;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class PasswordPolicy {
    public enum Result {
        OK,
        TOO_SHORT,
        TOO_LONG,
        BLACKLISTED,
        MISSING_REQUIRED
    }

    private final int minLength;
    private final int maxLength;
    private final boolean requireUppercase;
    private final boolean requireLowercase;
    private final boolean requireNumber;
    private final boolean requireSymbol;
    private final Set<String> blacklist;

    public PasswordPolicy(int minLength, int maxLength,
                          boolean requireUppercase, boolean requireLowercase,
                          boolean requireNumber, boolean requireSymbol,
                          List<String> blacklist) {
        this.minLength = Math.max(0, minLength);
        this.maxLength = maxLength;
        this.requireUppercase = requireUppercase;
        this.requireLowercase = requireLowercase;
        this.requireNumber = requireNumber;
        this.requireSymbol = requireSymbol;
        Set<String> temp = new HashSet<>();
        if (blacklist != null) {
            for (String item : blacklist) {
                if (item != null && !item.isBlank()) {
                    temp.add(item.toLowerCase(Locale.ROOT));
                }
            }
        }
        this.blacklist = temp;
    }

    public Result validate(String password) {
        if (password == null) {
            return Result.TOO_SHORT;
        }
        int len = password.length();
        if (len < minLength) {
            return Result.TOO_SHORT;
        }
        if (maxLength > 0 && len > maxLength) {
            return Result.TOO_LONG;
        }
        if (!blacklist.isEmpty()) {
            String lower = password.toLowerCase(Locale.ROOT);
            if (blacklist.contains(lower)) {
                return Result.BLACKLISTED;
            }
        }
        boolean hasUpper = !requireUppercase;
        boolean hasLower = !requireLowercase;
        boolean hasNumber = !requireNumber;
        boolean hasSymbol = !requireSymbol;
        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);
            if (Character.isUpperCase(c)) {
                hasUpper = true;
            } else if (Character.isLowerCase(c)) {
                hasLower = true;
            } else if (Character.isDigit(c)) {
                hasNumber = true;
            } else {
                hasSymbol = true;
            }
        }
        if (!hasUpper || !hasLower || !hasNumber || !hasSymbol) {
            return Result.MISSING_REQUIRED;
        }
        return Result.OK;
    }
}
