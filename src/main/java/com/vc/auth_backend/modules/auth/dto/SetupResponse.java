package com.vc.auth_backend.modules.auth.dto;

public record SetupResponse(
        String secret,
        String qrCodeUri,
        String qrCodeImage
) {}