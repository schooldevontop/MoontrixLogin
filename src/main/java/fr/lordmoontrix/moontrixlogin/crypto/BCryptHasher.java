package fr.lordmoontrix.moontrixlogin.crypto;

import at.favre.lib.crypto.bcrypt.BCrypt;

public final class BCryptHasher implements PasswordHasher {
    private final int cost;

    public BCryptHasher(int cost) {
        this.cost = cost;
    }

    @Override
    public String hash(char[] password) {
        return BCrypt.withDefaults().hashToString(cost, password);
    }

    @Override
    public boolean verify(char[] password, String hash) {
        BCrypt.Result result = BCrypt.verifyer().verify(password, hash);
        return result.verified;
    }
}
