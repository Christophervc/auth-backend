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

    public Bucket resolveBucket(String key, boolean isAuthRequest, boolean isOtpRequest) {
        return cache.get(key, k -> buildBucket(isAuthRequest, isOtpRequest));
    }

    public Bucket resolveBucket(String key, boolean isAuthRequest) {
        return resolveBucket(key, isAuthRequest, false);
    }

    private Bucket buildBucket(boolean isAuthRequest,  boolean isOtpRequest) {
        Bandwidth limit =  isOtpRequest  ? otpLimit
                : isAuthRequest ? authLimit
                : generalLimit;
        return Bucket.builder().addLimit(limit).build();
    }
}
