package fr.lordmoontrix.moontrixlogin.storage.migrations;

import fr.lordmoontrix.moontrixlogin.storage.Migration;

public final class V3_Totp implements Migration {
    @Override
    public int version() {
        return 3;
    }

    @Override
    public String description() {
        return "create totp table";
    }

    @Override
    public String mysqlSql() {
        return "CREATE TABLE IF NOT EXISTS ml_totp ("
            + "uuid VARCHAR(36) PRIMARY KEY,"
            + "secret VARCHAR(64) NOT NULL,"
            + "enabled BOOLEAN NOT NULL"
            + ")";
    }

    @Override
    public String sqliteSql() {
        return "CREATE TABLE IF NOT EXISTS ml_totp ("
            + "uuid TEXT PRIMARY KEY,"
            + "secret TEXT NOT NULL,"
            + "enabled INTEGER NOT NULL"
            + ")";
    }
}
