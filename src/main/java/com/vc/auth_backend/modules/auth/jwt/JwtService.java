package com.vc.auth_backend.modules.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {
    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.time.expiration}")
    private long jwtExpiration;

    @Value("${jwt.time.refresh-expiration}")
    private long refreshExpiration;

    @Value("${app.2fa.pre-auth-expiration}")
    private long preAuthExpiration;

    private SecretKey signingKey;

    @PostConstruct
    private void initSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(UserDetails userDetails){
        Map<String, Object> extraClaims = new HashMap<>();
        var authorities = userDetails.getAuthorities();
        if (authorities != null && !authorities.isEmpty()) {
            extraClaims.put("role", userDetails.getAuthorities().iterator().next().getAuthority());
        }
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public String generateRefreshToken(UserDetails userDetails){
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    public String generatePreAuthToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "pre_auth"); // claim discriminador
        return buildToken(claims, userDetails, preAuthExpiration);
    }

    public boolean isPreAuthToken(String token) {
        try {
            String type = extractClaims(token, claims -> claims.get("type", String.class));
            return "pre_auth".equals(type);
        } catch (Exception e) {
            return false;
        }
    }

    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        Instant now = Instant.now();
        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .id(UUID.randomUUID().toString())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(expiration)))
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        Claims claims = parseSignedClaims(token);
        return claims.getSubject().equals(userDetails.getUsername());
    }

    public Instant getExpirationDateFromToken(String token) {
        return extractClaims(token, claims -> claims.getExpiration().toInstant());
    }

    public String extractUsername(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    private<T> T extractClaims(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = parseSignedClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims parseSignedClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSigningKey() {
        return signingKey;
    }
}
