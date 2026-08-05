package com.vc.auth_backend.modules.auth.jwt;

import com.vc.auth_backend.modules.auth.security.CustomUserPrincipal;
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

    private SecretKey signingKey;

    // Nombres de claims custom embebidos en el access token
    static final String CLAIM_ROLE   = "role";
    static final String CLAIM_ACTIVE = "active";
    static final String CLAIM_UID    = "uid";
    static final String CLAIM_SID    = "sid";

    @PostConstruct
    private void initSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(UserDetails userDetails, UUID sessionId) {
        Map<String, Object> extraClaims = new HashMap<>();
        var authorities = userDetails.getAuthorities();
        if (authorities != null && !authorities.isEmpty()) {
            extraClaims.put(CLAIM_ROLE, authorities.iterator().next().getAuthority());
        }

        if (userDetails instanceof CustomUserPrincipal principal) {
            extraClaims.put(CLAIM_ACTIVE, principal.user().isActive());
            extraClaims.put(CLAIM_UID, principal.user().getId().toString());
        }
        extraClaims.put(CLAIM_SID, sessionId.toString());
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
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

    public Instant getExpirationDateFromToken(String token) {
        return extractClaim(token, claims -> claims.getExpiration().toInstant());
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
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
