package com.vc.auth_backend.modules.auth;

import com.vc.auth_backend.config.OpenApiConfig;
import com.vc.auth_backend.modules.auth.dto.*;
import com.vc.auth_backend.modules.auth.security.CustomUserPrincipal;
import com.vc.auth_backend.modules.auth.service.AuthenticationService;
import com.vc.auth_backend.modules.auth.service.CookieService;
import com.vc.auth_backend.modules.auth.service.PasswordResetService;
import com.vc.auth_backend.modules.auth.service.RefreshTokenService;
import com.vc.auth_backend.modules.user.controller.dto.MessageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Gestiona el ciclo de autenticacion y sesion de los usuarios.")
public class AuthController {

    private final AuthenticationService authenticationService;
    private final RefreshTokenService refreshTokenService;
    private final CookieService cookieService;
    private final PasswordResetService passwordResetService;

    @Operation(
            summary = "Iniciar sesion",
            description = "Autentica al usuario con credenciales y escribe las cookies http-only de acceso y refresh."
    )
    @PostMapping("/login")
    public ResponseEntity<MessageResponse> login(
            @Valid @RequestBody LoginRequest request,
            @Parameter(hidden = true) HttpServletResponse response) {
        AuthResponse authResponse = authenticationService.authenticate(request);
        cookieService.addAuthCookies(response, authResponse);
        return ResponseEntity.ok(new MessageResponse("Login successfully"));
    }

    @Operation(
            summary = "Registrar usuario",
            description = "Crea una nueva cuenta y devuelve las cookies http-only necesarias para iniciar sesion."
    )
    @PostMapping("/register")
    public ResponseEntity<MessageResponse> register(
            @Valid @RequestBody RegisterRequest request,
            @Parameter(hidden = true) HttpServletResponse response) {
        AuthResponse authResponse = authenticationService.register(request);
        cookieService.addAuthCookies(response, authResponse);
        return new ResponseEntity<>(new MessageResponse(authResponse.message()), HttpStatus.CREATED);
    }

    @Operation(
            summary = "Refrescar sesion",
            description = "Renueva el access token usando la cookie http-only refresh_token y vuelve a escribir las cookies de autenticacion."
    )
    @PostMapping("/refresh")
    public ResponseEntity<MessageResponse> refresh(
            @Parameter(hidden = true) HttpServletRequest request,
            @Parameter(hidden = true) HttpServletResponse response) {
        String token = cookieService.getRefreshToken(request)
                .orElseThrow(() -> new IllegalArgumentException("Refresh token cookie not found"));
        AuthResponse auth = authenticationService.refreshToken(new RefreshTokenRequest(token));
        cookieService.addAuthCookies(response, auth);
        return ResponseEntity.ok(new MessageResponse("Token refreshed"));
    }

    @Operation(
            summary = "Cerrar sesion actual",
            description = "Invalida la sesion asociada al refresh token recibido por cookie y limpia las cookies de autenticacion del navegador."
    )
    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(
            @Parameter(hidden = true) HttpServletRequest request,
            @Parameter(hidden = true) HttpServletResponse response) {
        cookieService.getRefreshToken(request).ifPresent(refreshTokenService::logout);
        cookieService.clearAuthCookies(response);
        return ResponseEntity.ok(new MessageResponse("Logged out successfully"));
    }

    @Operation(
            summary = "Cerrar todas las sesiones",
            description = "Revoca todas las sesiones activas del usuario autenticado y elimina las cookies actuales.",
            security = {
                    @SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME),
                    @SecurityRequirement(name = OpenApiConfig.COOKIE_SCHEME)
            }
    )
    @PostMapping("/logout-all")
    public ResponseEntity<MessageResponse> logoutAll(
            @Parameter(hidden = true) @AuthenticationPrincipal CustomUserPrincipal currentUser,
            @Parameter(hidden = true) HttpServletResponse response) {
        refreshTokenService.logoutAll(currentUser.getId());
        cookieService.clearAuthCookies(response);
        return ResponseEntity.ok(new MessageResponse("All sessions logged out"));
    }

    @Operation(
            summary = "Solicitar codigo de recuperacion",
            description = """
                    Envía un código OTP de 6 dígitos al email indicado.
                    Responde 200 OK sin revelar si el email está registrado (email enumeration)
                    El código expira en 10 minutos y es de un solo uso.
                    Rate limit: 3 solicitudes por hora por IP.
                    """
    )
    @PostMapping("/forgot-password")
    public ResponseEntity<MessageResponse> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        passwordResetService.requestPasswordReset(request);
        return ResponseEntity.ok(new MessageResponse("If the email is registered, you will receive a recovery code shortly."));
    }

    @Operation(
            summary = "Verificar codigo OTP",
            description = """
                    Valida que el código OTP sea correcto y no haya expirado.
                    NO consume el código ni cambia la contraseña.
                    Paso intermedio para que el frontend confirme el código antes de mostrar el formulario de nueva contraseña.
                    """
    )
    @PostMapping("/verify-otp")
    public ResponseEntity<MessageResponse> verifyOtp(@Valid @RequestBody VerifyOtpRequest request) {
        passwordResetService.verifyOtp(request);
        return ResponseEntity.ok(new MessageResponse("Code is valid. You can now reset your password."));
    }

    @Operation(
            summary = "Restablecer contrasena",
            description = """
                    Valida el código OTP y establece la nueva contraseña.
                    Si el código es válido:
                      - La nueva contraseña queda establecida.
                      - El código OTP se marca como usado (no reutilizable).
                      - Todas las sesiones activas del usuario son revocadas.
                    """
    )
    @PostMapping("/reset-password")
    public ResponseEntity<MessageResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        passwordResetService.resetPassword(request);
        return ResponseEntity.ok(new MessageResponse("Password updated successfully. Please log in with your new password."));
    }
}
