package com.vc.auth_backend.modules.auth.repository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Repository
@RequiredArgsConstructor
public class OtpRedisRepository {
    private final StringRedisTemplate redisTemplate;

    @Value("${app.otp.expiration-minutes}")
    private int expirationMinutes;

    private static final String KEY_PREFIX = "otp:password_reset";

    // Escritura
    public void save(UUID userId, String codeHash) {
        String key = buildKey(userId);
        Duration ttl = Duration.ofMinutes(expirationMinutes);
        redisTemplate.opsForValue().set(key, codeHash, ttl);
        log.debug("OTP saved in Redis for userId={} TTL={}min", userId, expirationMinutes);
    }

    // Lectura
    public Optional<String> findHash(UUID userId) {
        String hash = redisTemplate.opsForValue().get(buildKey(userId));
        return Optional.ofNullable(hash);
    }

    // Eliminación
    public void delete(UUID userId) {
        String key = buildKey(userId);
        Boolean deleted = redisTemplate.delete(key);
        log.debug("OTP deleted from Redis for userId={} deleted={}", userId, deleted);
    }

    private String buildKey(UUID userId) {
        return KEY_PREFIX + userId.toString();
    }
}
