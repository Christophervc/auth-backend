package com.vc.auth_backend.modules.auth;

import com.vc.auth_backend.config.OpenApiConfig;
import com.vc.auth_backend.modules.auth.dto.AuthResponse;
import com.vc.auth_backend.modules.auth.dto.ConfirmSetupResponse;
import com.vc.auth_backend.modules.auth.dto.SetupResponse;
import com.vc.auth_backend.modules.auth.dto.TwoFactorCodeRequest;
import com.vc.auth_backend.modules.auth.security.CustomUserPrincipal;
import com.vc.auth_backend.modules.auth.service.CookieService;
import com.vc.auth_backend.modules.auth.service.TwoFactorService;
import com.vc.auth_backend.modules.user.controller.dto.MessageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth/2fa")
@RequiredArgsConstructor
@Tag(name = "Two Factor Authentication", description = "Endpoints para gestionar y verificar TOTP 2FA")
public class TwoFactorController {
    private final TwoFactorService twoFactorService;
    private final CookieService cookieService;

    @Operation(summary = "Paso 1: Configurar 2FA", description = "Genera el QR y el secreto. Requiere estar autenticado.",
            security = {@SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME), @SecurityRequirement(name = OpenApiConfig.COOKIE_SCHEME)})
    @PostMapping("/setup")
    public ResponseEntity<SetupResponse> setup2fa(
            @Parameter(hidden = true) @AuthenticationPrincipal CustomUserPrincipal currentUser) {
        return ResponseEntity.ok(twoFactorService.setup(currentUser.getId()));
    }

    @Operation(summary = "Paso 2: Confirmar 2FA", description = "Verifica el primer código para activar 2FA y devuelve los backup codes.",
            security = {@SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME), @SecurityRequirement(name = OpenApiConfig.COOKIE_SCHEME)})
    @PostMapping("/confirm-setup")
    public ResponseEntity<ConfirmSetupResponse> confirmSetup(
            @Valid @RequestBody TwoFactorCodeRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal CustomUserPrincipal currentUser) {
        return ResponseEntity.ok(twoFactorService.confirmSetup(currentUser.getId(), request.code()));
    }

    @Operation(summary = "Completar Login 2FA", description = "Recibe el código TOTP y el pre-auth token (por cookie) para emitir los tokens finales.")
    @PostMapping("/verify")
    public ResponseEntity<AuthResponse> verifyLogin(
            @Valid @RequestBody TwoFactorCodeRequest request,
            @Parameter(hidden = true) HttpServletRequest httpRequest,
            @Parameter(hidden = true) HttpServletResponse httpResponse) {
        String preAuthToken = cookieService.getPreAuthToken(httpRequest)
                .orElseThrow(() -> new IllegalArgumentException("Pre-auth token is missing. Please login first."));
        AuthResponse authResponse = twoFactorService.verifyLogin(preAuthToken, request.code(), httpRequest);
        cookieService.clearPreAuthCookie(httpResponse);
        cookieService.addAuthCookies(httpResponse, authResponse);
        return ResponseEntity.ok(authResponse);
    }

    @Operation(summary = "Desactivar 2FA", description = "Desactiva 2FA validando un código actual. Requiere estar autenticado.",
            security = {@SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME), @SecurityRequirement(name = OpenApiConfig.COOKIE_SCHEME)})
    @PostMapping("/disable")
    public ResponseEntity<MessageResponse> disable2fa(
            @Valid @RequestBody TwoFactorCodeRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal CustomUserPrincipal currentUser) {
        twoFactorService.disable(currentUser.getId(), request.code());
        return ResponseEntity.ok(new MessageResponse("2FA has been disabled successfully"));
    }
}
