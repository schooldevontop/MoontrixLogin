package fr.lordmoontrix.moontrixlogin.storage;

public enum DatabaseType {
    MYSQL,
    SQLITE;

    public static DatabaseType from(String value) {
        if (value == null) {
            return SQLITE;
        }
        try {
            return DatabaseType.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            return SQLITE;
        }
    }
}
