package com.vc.auth_backend.modules.auth.repository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Slf4j
@Repository
@RequiredArgsConstructor
public class SessionRedisRepository {
    private final StringRedisTemplate redisTemplate;

    private static final String KEY_PREFIX = "session:active:";

    public void save(UUID sessionId, UUID userId, Instant expiryDate){
        Duration ttl = Duration.between(Instant.now(), expiryDate);
        if (ttl.isNegative() || ttl.isZero()) {
            log.warn("Try to save session {} with non-positive TTL, session skipped", sessionId);
            return;
        }
        redisTemplate.opsForValue().set(buildKey(sessionId), userId.toString(), ttl);
        log.debug("Sesión marcada activa en Redis sessionId={} TTL={}", sessionId, ttl);
    }

    public boolean exists(UUID sessionId) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(buildKey(sessionId)));
    }

    public void delete(UUID sessionId) {
        Boolean deleted = redisTemplate.delete(buildKey(sessionId));
        log.debug("Session deleted from Redis sessionId={} deleted={}",sessionId, deleted);
    }

    private String buildKey(UUID sessionId) {
        return KEY_PREFIX + sessionId;
    }
}
