package fr.lordmoontrix.moontrixlogin.session;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.SecretKey;

public final class JwtSessionTokenService {
    private final SecretKey signingKey;
    private final String issuer;
    private final int rememberMeTtlDays;

    public JwtSessionTokenService(String secret, String issuer, int rememberMeTtlDays) {
        this.signingKey = Keys.hmacShaKeyFor(normalizeSecret(secret));
        this.issuer = issuer;
        this.rememberMeTtlDays = Math.max(1, rememberMeTtlDays);
    }

    public String issueRememberToken(UUID uuid, String fingerprint, String ipPrefix) {
        Instant now = Instant.now();
        Instant expires = now.plus(rememberMeTtlDays, ChronoUnit.DAYS);
        return Jwts.builder()
            .issuer(issuer)
            .subject(uuid.toString())
            .claim("fp", fingerprint)
            .claim("ipp", ipPrefix)
            .issuedAt(Date.from(now))
            .expiration(Date.from(expires))
            .signWith(signingKey, Jwts.SIG.HS256)
            .compact();
    }

    public Optional<TokenClaims> validateRememberToken(String token) {
        try {
            Jws<Claims> parsed = Jwts.parser().verifyWith(signingKey).build()
                .parseSignedClaims(token);
            Claims claims = parsed.getPayload();
            String sub = claims.getSubject();
            String fp = claims.get("fp", String.class);
            String ipPrefix = claims.get("ipp", String.class);
            if (sub == null || fp == null || ipPrefix == null) {
                return Optional.empty();
            }
            return Optional.of(new TokenClaims(UUID.fromString(sub), fp, ipPrefix));
        } catch (Exception ex) {
            return Optional.empty();
        }
    }

    private byte[] normalizeSecret(String secret) {
        String source = secret == null ? "" : secret.trim();
        if (source.isBlank()) {
            throw new IllegalArgumentException("JWT secret is required. Set MOONTRIX_JWT_SECRET.");
        }
        if (source.length() < 32) {
            throw new IllegalArgumentException("JWT secret must be at least 32 characters.");
        }
        return source.getBytes(StandardCharsets.UTF_8);
    }

    public record TokenClaims(UUID uuid, String fingerprint, String ipPrefix) {
    }
}
