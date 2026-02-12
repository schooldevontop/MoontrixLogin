package fr.lordmoontrix.moontrixlogin.crypto;

public interface PasswordHasher {
    String hash(char[] password);

    boolean verify(char[] password, String hash);
}
