package com.vc.auth_backend.modules.user.controller.dto;

import jakarta.validation.constraints.NotNull;

public record UpdateUserStatusReq(
        @NotNull(message = "Active status is required") Boolean active) {
}
