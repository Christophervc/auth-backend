package com.vc.auth_backend.modules.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record TwoFactorCodeRequest(
        @NotBlank(message = "Code is required")
        @Pattern(regexp = "^[a-zA-Z0-9]{6,10}$", message = "Invalid code format")
        String code) {
}
