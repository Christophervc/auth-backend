package com.vc.auth_backend.config.ratelimit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Service
public class RateLimitingService {
    private final Cache<String, Bucket> cache = Caffeine.newBuilder()
            .maximumSize(100_000)
            .expireAfterAccess(2, TimeUnit.HOURS)
            .build();

    private final Bandwidth generalLimit = Bandwidth.builder()
            .capacity(90)
            .refillGreedy(90, Duration.ofMinutes(1))
            .build();

    private final Bandwidth authLimit = Bandwidth.builder()
            .capacity(10)
            .refillIntervally(10, Duration.ofMinutes(1))
            .build();

    private final Bandwidth otpLimit = Bandwidth.builder()
            .capacity(3)
            .refillIntervally(3, Duration.ofHours(1))
            .build();

    private final Bandwidth totpLimit = Bandwidth.builder()
            .capacity(5)
            .refillIntervally(5, Duration.ofMinutes(15))
            .build();

    /**
     * Resuelve un bucket de rate limiting basado en el tipo y el identificador del cliente.
     * @param type El tipo de bucket (TOTP, AUTH, OTP, GEN)
     * @param clientId El ID del usuario o la IP
     * @return El bucket correspondiente
     */
    public Bucket resolveBucket(String type, String clientId) {
        String key = type + ":" + clientId;
        return cache.get(key, k -> createBucket(type));
    }

    private Bucket createBucket(String type) {
        Bandwidth limit = switch (type) {
            case "TOTP" -> totpLimit;
            case "AUTH" -> authLimit;
            case "OTP"  -> otpLimit;
            default     -> generalLimit;
        };
        return Bucket.builder().addLimit(limit).build();
    }
}
