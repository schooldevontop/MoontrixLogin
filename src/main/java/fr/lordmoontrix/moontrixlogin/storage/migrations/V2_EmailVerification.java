package fr.lordmoontrix.moontrixlogin.storage.migrations;

import fr.lordmoontrix.moontrixlogin.storage.Migration;

public final class V2_EmailVerification implements Migration {
    @Override
    public int version() {
        return 2;
    }

    @Override
    public String description() {
        return "create email verification table";
    }

    @Override
    public String mysqlSql() {
        return "CREATE TABLE IF NOT EXISTS ml_email_verifications ("
            + "uuid VARCHAR(36) PRIMARY KEY,"
            + "email VARCHAR(255) NOT NULL,"
            + "code VARCHAR(12) NOT NULL,"
            + "expires_at TIMESTAMP"
            + ")";
    }

    @Override
    public String sqliteSql() {
        return "CREATE TABLE IF NOT EXISTS ml_email_verifications ("
            + "uuid TEXT PRIMARY KEY,"
            + "email TEXT NOT NULL,"
            + "code TEXT NOT NULL,"
            + "expires_at TEXT"
            + ")";
    }
}


