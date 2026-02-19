# MoontrixLogin Hardening Guide

This guide maps directly to the critical findings and explains how to migrate safely.

## 1) Credentials in plaintext

`config.yml` now supports secure secret references:

- `ENV`: `${ENV:MOONTRIX_DB_PASSWORD}`
- `AES-GCM`: `${AES_GCM:BASE64_PAYLOAD}`
- `Vault`: `${VAULT:secret/data/moontrixlogin#db_password}`

Example:

```yaml
storage:
  mysql:
    password: "${ENV:MOONTRIX_DB_PASSWORD}"
mail:
  password: "${VAULT:secret/data/moontrixlogin#smtp_password}"
```

Important:
- Secret resolution is now fail-fast for referenced secrets.
- If `${AES_GCM:...}` or `${VAULT:...}` cannot be resolved, plugin startup is blocked with explicit logs.

Environment variables:

```powershell
$env:MOONTRIX_DB_PASSWORD="your_db_password"
$env:MOONTRIX_SMTP_PASSWORD="your_smtp_password"
$env:MOONTRIX_JWT_SECRET="replace_with_32_plus_chars"
$env:MOONTRIX_CONFIG_AES_KEY="base64_32_byte_aes_key"
$env:MOONTRIX_VAULT_ADDR="https://vault.example.com"
$env:MOONTRIX_VAULT_TOKEN="vault-token"
```

AES encryption example (Java):

```java
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

String keyB64 = System.getenv("MOONTRIX_CONFIG_AES_KEY");
byte[] key = Base64.getDecoder().decode(keyB64);
byte[] iv = new byte[12];
new SecureRandom().nextBytes(iv);
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
byte[] cipher = c.doFinal("secret-value".getBytes(StandardCharsets.UTF_8));
byte[] packed = ByteBuffer.allocate(iv.length + cipher.length).put(iv).put(cipher).array();
String ref = "${AES_GCM:" + Base64.getEncoder().encodeToString(packed) + "}";
System.out.println(ref);
```

## 2) Brute-force protection

Default schedule is now progressive:

- 1 hour
- 24 hours
- 7 days
- permanent (`0`)

Config:

```yaml
security:
  bruteForce:
    maxAttempts: 5
    windowSeconds: 300
    progressiveLockSeconds: [3600, 86400, 604800, 0]
```

Additional controls:

- Adaptive CAPTCHA when suspicious activity is detected
- Device fingerprint failure tracking and temporary device bans
- Optional AbuseIPDB reputation checks with local cache

## 3) Dependency security

Implemented:

- Added missing Caffeine dependency (build fix)
- Added JWT library (`jjwt`) for signed session tokens
- Added direct `commons-logging` override
- Added OWASP dependency check plugin to Maven
- Added `.github/dependabot.yml`
- Added `.github/workflows/security.yml`

Run locally:

```bash
./mvnw -DskipTests org.owasp:dependency-check-maven:check
```

## 4) Session management

Session validation now uses:

- IP prefix matching
- Device fingerprint matching
- Signed JWT remember token

Remember-me flow:

1. Player logs in with `/login <password> [totp] remember`
2. Plugin issues signed JWT with UUID + fingerprint + IP prefix
3. On next join, if token context matches, player auto-authenticates

Persistence:
- Remember tokens are persisted in `plugins/MoontrixLogin/remember-tokens.properties`.
- Stored remember token file is encrypted at rest (AES-GCM) when JWT secret is configured.
- `/logout` and successful `/unregister` revoke stored remember token.
- If decryption fails (for example after rotating JWT secret), old remember tokens are invalidated automatically and the unreadable file is quarantined with `.invalid-<timestamp>` suffix.

## 5) Caching

Caffeine cache is enabled in config by default:

```yaml
storage:
  cache:
    enabled: true
    ttlSeconds: 60
    maxEntries: 10000
```

Invalidation:

- Create/update/delete operations invalidate or update cache immediately
- Join flow naturally warms cache via `findByUuid`

For multi-server deployments, use Redis as an external invalidation/event bus layer.

## 6) Database pool sizing

Defaults upgraded:

- `poolSize: 50`
- `minimumIdle: 8`
- leak detection enabled (`2000ms`)
- pool usage warning logs at high utilization

Hikari tuning now includes keepalive, validation timeout, prepared statement cache options, and JMX MBeans.

## 7) Blocking I/O

Current state:

- DB repositories are already async (`CompletableFuture` + dedicated worker pool)
- Email sending is async
- IP reputation checks are now non-blocking on main thread (async refresh + cached reads)

This removes network waits from login/register command execution path.
