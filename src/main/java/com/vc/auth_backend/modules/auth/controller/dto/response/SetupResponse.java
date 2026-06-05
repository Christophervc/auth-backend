package com.vc.auth_backend.modules.auth.controller.dto.response;

public record SetupResponse(
        String secret,
        String qrCodeUri,
        String qrCodeImage
) {}