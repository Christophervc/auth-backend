package com.vc.auth_backend.modules.auth.repository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.util.Optional;

@Slf4j
@Repository
@RequiredArgsConstructor
public class PreAuthRedisRepository {
    private final StringRedisTemplate redisTemplate;

    private static final String KEY_PREFIX = "2fa:preauth:";

    @Value("${app.2fa.pre-auth-expiration-minutes:5}")
    private int preAuthExpirationMinutes;

    public void save(String token, String email){
        String key = buildKey(token);
        redisTemplate.opsForValue().set(key, email, Duration.ofMinutes(preAuthExpirationMinutes));
        log.debug("Pre-auth token saved in Redis for email={} TTL={}min", email, preAuthExpirationMinutes);
    }

    public Optional<String> findEmailByToken(String token){
       return Optional.ofNullable(redisTemplate.opsForValue().get(buildKey(token)));
    }

    public void delete(String token) {
        redisTemplate.delete(buildKey(token));
        log.debug("Pre-auth token deleted from Redis");
    }

    private String buildKey(String token) {
        return KEY_PREFIX + token;
    }
}
