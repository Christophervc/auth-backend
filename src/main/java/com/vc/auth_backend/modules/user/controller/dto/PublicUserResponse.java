package com.vc.auth_backend.modules.user.controller.dto;

import java.time.LocalDateTime;
import java.util.UUID;

public record PublicUserResponse(
        UUID id,
        String name,
        String lastname,
        LocalDateTime joinedAt
) {}