package com.vc.auth_backend.modules.auth.repository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.util.UUID;

@Slf4j
@Repository
@RequiredArgsConstructor
public class UsedTotpCodeRedisRepository {

    private final StringRedisTemplate redisTemplate;

    private static final String KEY_PREFIX = "2fa:used-totp:";

    public boolean markAsUsedIfNew(UUID userId, String code, int periodSeconds) {
        String key = buildKey(userId, code);
        // TTL = 2 períodos: cubre el período anterior + el actual (ventana ±1)
        Duration ttl = Duration.ofSeconds((long) periodSeconds * 2);
        Boolean isNew = redisTemplate.opsForValue().setIfAbsent(key, "1", ttl);
        boolean accepted = Boolean.TRUE.equals(isNew);
        if (!accepted) {
            log.warn("TOTP replay attempt blocked for userId={}", userId);
        }
        return accepted;
    }

    private String buildKey(UUID userId, String code) {
        // Key única por usuario + código. El TTL garantiza que no crece indefinidamente.
        return KEY_PREFIX + userId + ":" + code;
    }
}
