package com.vc.auth_backend.modules.auth.controller.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record LoginResponse(String message, Boolean requiresTwoFactor) {

    public static LoginResponse of(String message) {
        return new LoginResponse(message, null);
    }

    public static LoginResponse twoFactorRequired(String message) {
        return new LoginResponse(message, true);
    }
}