package fr.lordmoontrix.moontrixlogin.storage;

public interface Migration {
    int version();

    String description();

    String mysqlSql();

    String sqliteSql();
}


