package fr.lordmoontrix.moontrixlogin.storage.migrations;

import fr.lordmoontrix.moontrixlogin.storage.Migration;

public final class V1_CreateUsers implements Migration {
    @Override
    public int version() {
        return 1;
    }

    @Override
    public String description() {
        return "create users table";
    }

    @Override
    public String mysqlSql() {
        return "CREATE TABLE IF NOT EXISTS ml_users ("
            + "uuid VARCHAR(36) PRIMARY KEY,"
            + "username VARCHAR(16) NOT NULL,"
            + "password VARCHAR(255) NOT NULL,"
            + "email VARCHAR(255),"
            + "reg_ip VARCHAR(45),"
            + "last_ip VARCHAR(45),"
            + "reg_time TIMESTAMP,"
            + "last_login TIMESTAMP,"
            + "INDEX idx_username (username)"
            + ")";
    }

    @Override
    public String sqliteSql() {
        return "CREATE TABLE IF NOT EXISTS ml_users ("
            + "uuid TEXT PRIMARY KEY,"
            + "username TEXT NOT NULL,"
            + "password TEXT NOT NULL,"
            + "email TEXT,"
            + "reg_ip TEXT,"
            + "last_ip TEXT,"
            + "reg_time TEXT,"
            + "last_login TEXT"
            + ")";
    }
}


