package com.vc.auth_backend.modules.user.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record UpdateUserProfileReq(
        @NotBlank(message = "Name cannot be empty")
        @Size(min = 2, max = 50)
        String name,
        @NotBlank(message = "Last name cannot be empty")
        @Size(min = 2, max = 80)
        String lastname,
        @NotBlank(message = "Phone number cannot be empty")
        @Pattern(regexp = "^\\+?[0-9]{5,20}$", message = "Phone must be 5 to 20 digits, optionally starting with +")
        String phone
) {
}