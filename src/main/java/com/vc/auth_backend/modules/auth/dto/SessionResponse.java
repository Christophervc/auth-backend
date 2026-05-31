package com.vc.auth_backend.modules.auth.dto;

import com.vc.auth_backend.modules.auth.entity.DeviceType;

import java.time.Instant;
import java.util.UUID;

public record SessionResponse(
        UUID id,
        String deviceName,
        String os,
        DeviceType deviceType,
        String ipAddress,
        Instant lastUsedAt,
        Instant createdAt,
        Instant expiresAt,
        boolean current) {
}
