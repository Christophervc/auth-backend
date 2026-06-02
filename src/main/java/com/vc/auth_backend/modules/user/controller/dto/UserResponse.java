package com.vc.auth_backend.modules.user.controller.dto;

import com.vc.auth_backend.modules.user.entity.Role;

import java.time.LocalDateTime;
import java.util.UUID;

public record UserResponse(
        UUID id,
        String name,
        String lastname,
        String email,
        String phone,
        String language,
        String country,
        Role role,
        boolean active,
        LocalDateTime joinedAt,
        String avatar,
        String provider,
        boolean twoFactorEnabled
) {
}
