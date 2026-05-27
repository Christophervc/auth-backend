package com.vc.auth_backend.modules.user.controller.dto;
import com.vc.auth_backend.modules.user.entity.Role;
import jakarta.validation.constraints.NotNull;

public record UpdateUserRoleReq(
        @NotNull(message = "Role is required")
        Role role
) {}