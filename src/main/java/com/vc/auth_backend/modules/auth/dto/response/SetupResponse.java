package com.vc.auth_backend.modules.auth.dto.response;

public record SetupResponse(
        String secret,
        String qrCodeUri,
        String qrCodeImage
) {}