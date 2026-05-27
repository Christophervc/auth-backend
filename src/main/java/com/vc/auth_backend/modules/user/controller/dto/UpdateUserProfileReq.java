package com.vc.auth_backend.modules.user.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdateUserProfileReq(
        @NotBlank(message = "Name cannot be empty")
        @Size(min = 2, max = 50)
        String name,
        @Size(max = 500)
        String bio
) {}