package com.vc.auth_backend.modules.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.Pattern;

public record ResetPasswordRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        String email,

        @NotBlank(message = "OTP code is required")
        @Pattern(regexp = "\\d{6}", message = "OTP must be exactly 6 digits")
        String code,

        @NotBlank(message = "New password is required")
        @Size(min = 8, message = "Password must be at least {min} characters")
        @Pattern(
                regexp = "^(?=.*[A-Z])(?=.*\\d).*$",
                message = "Password must contain at least one uppercase letter and one number")
        String newPassword
) {
}
