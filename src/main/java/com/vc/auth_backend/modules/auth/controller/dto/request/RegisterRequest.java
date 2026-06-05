package com.vc.auth_backend.modules.auth.controller.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "Full name is mandatory")
        @Size(min = 3, max = 30, message = "Full name must be between 3 and 30 characters")
        String fullName,

        @NotBlank(message = "Email is mandatory")
        @Email(message = "Invalid email format")
        String email,

        @NotBlank(message = "Password is required")
        @Size(min = 8, message = "Password must be at least {min} characters")
        @Pattern(regexp = "^(?=.*[A-Z])(?=.*\\d).*$",
                message = "Password must contain at least one uppercase letter and one number")
        String password,

        @NotBlank(message = "Confirm password is required")
        String confirmPassword
) {
}
