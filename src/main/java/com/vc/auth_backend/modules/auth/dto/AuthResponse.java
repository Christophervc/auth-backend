package com.vc.auth_backend.modules.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthResponse(
        String token,
        String message,
        String refreshToken,
        Boolean requiresTwoFactor,
        String preAuthToken) {
}
