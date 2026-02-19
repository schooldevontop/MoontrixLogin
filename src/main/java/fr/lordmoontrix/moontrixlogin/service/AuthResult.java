package fr.lordmoontrix.moontrixlogin.service;

public final class AuthResult {
    public enum Code {
        OK,
        WRONG_PASSWORD,
        UNREGISTERED,
        LOCKED,
        ERROR
    }

    private final boolean success;
    private final String message;
    private final Code code;

    private AuthResult(boolean success, String message, Code code) {
        this.success = success;
        this.message = message;
        this.code = code;
    }

    public static AuthResult ok(String message) {
        return new AuthResult(true, message, Code.OK);
    }

    public static AuthResult fail(String message) {
        return new AuthResult(false, message, Code.ERROR);
    }

    public static AuthResult fail(Code code, String message) {
        return new AuthResult(false, message, code);
    }

    public boolean isSuccess() {
        return success;
    }

    public String getMessage() {
        return message;
    }

    public Code getCode() {
        return code;
    }
}


