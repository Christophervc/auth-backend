package com.vc.auth_backend.modules.user.controller.dto;

import com.vc.auth_backend.modules.user.entity.Role;

import java.time.LocalDateTime;
import java.util.UUID;

public record UserResponse(
        UUID id,
        String name,
        String fullName,
        String email,
        Role role,
        boolean active,
        LocalDateTime joinedAt) {
}
