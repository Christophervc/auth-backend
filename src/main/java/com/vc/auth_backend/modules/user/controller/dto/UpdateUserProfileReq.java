package com.vc.auth_backend.modules.user.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdateUserProfileReq(
        @NotBlank(message = "Name cannot be empty")
        @Size(min = 2, max = 50)
        String name,
        @NotBlank(message = "Last name cannot be empty")
        @Size( min =2, max = 500)
        String lastname
) {}