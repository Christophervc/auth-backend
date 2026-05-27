package com.vc.auth_backend.modules.user.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record ChangePasswordReq(
        @NotBlank(message = "Current password is required")
        String oldPassword,

        @NotBlank(message = "New Password is required")
        @Size(min = 6, message = "Password must be at least {min} characters long")
        @Pattern(regexp = "^(?=.*[A-Z])(?=.*\\d).*$",
                message = "Password must contain at least one uppercase letter and one number")
        String newPassword
) {}