package com.vc.auth_backend.modules.auth.dto.response;

import lombok.Builder;

//DTO interno
@Builder
public record AuthResponse(
        String token,
        String refreshToken,
        String preAuthToken,
        Boolean requiresTwoFactor,
        String message) {
}
