package com.vc.auth_backend.modules.auth.dto;

import lombok.Builder;

@Builder
public record AuthResponse(
        String token,
        String message,
        String refreshToken) {
}
