package com.vc.auth_backend.modules.auth.controller;

import com.vc.auth_backend.config.OpenApiConfig;
import com.vc.auth_backend.modules.auth.controller.dto.request.*;
import com.vc.auth_backend.modules.auth.controller.dto.response.AuthResponse;
import com.vc.auth_backend.modules.auth.controller.dto.response.LoginResponse;
import com.vc.auth_backend.modules.auth.controller.dto.response.SessionResponse;
import com.vc.auth_backend.modules.auth.security.CustomUserPrincipal;
import com.vc.auth_backend.modules.auth.service.*;
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
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Gestiona el ciclo de autenticacion y sesion de los usuarios.")
public class AuthController {

    private final AuthenticationService authenticationService;
    private final RefreshTokenService refreshTokenService;
    private final CookieService cookieService;
    private final PasswordResetService passwordResetService;
    private final EmailVerificationService emailVerificationService;

    @Operation(
            summary = "Iniciar sesión",
            description = "Autentica al usuario con credenciales y escribe las cookies http-only de acceso y refresh." +
                    "Registra el dispositivo (browser, OS) para la lista de sesiones." +
                    "Si tiene 2FA activo, retorna un estado pre-auth y escribe cookie temporal.")
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            @Parameter(hidden = true) HttpServletRequest httpRequest,
            @Parameter(hidden = true) HttpServletResponse httpResponse) {
        AuthResponse internal = authenticationService.authenticate(request, httpRequest);
        if (Boolean.TRUE.equals(internal.requiresTwoFactor())) {
            cookieService.addPreAuthCookie(httpResponse, internal.preAuthToken());
            return ResponseEntity.ok(LoginResponse.twoFactorRequired(internal.message()));
        }
        cookieService.addAuthCookies(httpResponse, internal);
        return ResponseEntity.ok(LoginResponse.of(internal.message()));
    }

    @Operation(
            summary = "Registrar usuario",
            description = """
                Crea una cuenta local pendiente de verificación y envía un código por email.
                La respuesta es siempre la misma sin importar si el correo ya existía
                (protección contra email enumeration). No inicia sesión: hay que
                verificar el email y luego usar /login.
                """)
    @PostMapping("/register")
    public ResponseEntity<MessageResponse> register(
            @Valid @RequestBody RegisterRequest request,
            @Parameter(hidden = true) HttpServletRequest httpRequest) {
        AuthResponse authResponse = authenticationService.register(request, httpRequest);
        return ResponseEntity.ok(new MessageResponse(authResponse.message()));
    }

    @Operation(
            summary = "Verificar email",
            description = "Valida el código enviado al email y marca la cuenta como verificada. Idempotente.")
    @PostMapping("/verify-email")
    public ResponseEntity<MessageResponse> verifyEmail(@Valid @RequestBody VerifyEmailRequest request) {
        emailVerificationService.verifyEmail(request);
        return ResponseEntity.ok(new MessageResponse("Email verified successfully. You can now log in."));
    }

    @Operation(
            summary = "Reenviar código de verificación",
            description = """
                Reenvía el código de verificación de email.
                Responde 200 OK sin revelar si el email está registrado o ya verificado.
                """)
    @PostMapping("/resend-verification")
    public ResponseEntity<MessageResponse> resendVerification(@Valid @RequestBody ResendVerificationRequest request) {
        emailVerificationService.resendVerification(request);
        return ResponseEntity.ok(new MessageResponse("If the email is registered and pending verification, a new code has been sent."));
    }

    @Operation(
            summary = "Refrescar sesion",
            description = "Rota el refresh token. Actualiza lastUsedAt de la sesion actual.")
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
            description = "Revoca la sesion asociada al refresh token de la cookie.")
    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(
            @Parameter(hidden = true) HttpServletRequest request,
            @Parameter(hidden = true) HttpServletResponse response) {
        cookieService.getRefreshToken(request).ifPresent(refreshTokenService::logout);
        cookieService.clearAuthCookies(response);
        return ResponseEntity.ok(new MessageResponse("Logged out successfully"));
    }

    @Operation(summary = "Cerrar todas las sesiones",
            description = "Revoca todas las sesiones activas del usuario autenticado y elimina las cookies actuales.",
            security = {
                    @SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME),
                    @SecurityRequirement(name = OpenApiConfig.COOKIE_SCHEME)
            })
    @PostMapping("/logout-all")
    public ResponseEntity<MessageResponse> logoutAll(
            @Parameter(hidden = true) @AuthenticationPrincipal CustomUserPrincipal currentUser,
            @Parameter(hidden = true) HttpServletResponse response) {
        refreshTokenService.logoutAll(currentUser.getId());
        cookieService.clearAuthCookies(response);
        return ResponseEntity.ok(new MessageResponse("All sessions logged out"));
    }

    // Gestion de sesiones
    @Operation(
            summary = "Listar sesiones activas",
            description = """
                    Devuelve todas las sesiones activas del usuario autenticado,
                    ordenadas por última actividad (más reciente primero).
                    Cada sesión incluye el dispositivo, OS, IP y un flag 'current'
                    que indica si es la sesión desde la que se hace esta request.
                    """,
            security = {
                    @SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME),
                    @SecurityRequirement(name = OpenApiConfig.COOKIE_SCHEME)
            }
    )
    @GetMapping("/sessions")
    public ResponseEntity<List<SessionResponse>> getSessions(
            @Parameter(hidden = true) @AuthenticationPrincipal CustomUserPrincipal currentUser,
            @Parameter(hidden = true) HttpServletRequest request) {
        String currentRefreshToken = cookieService.getRefreshToken(request).orElse(null);
        List<SessionResponse> sessions = refreshTokenService
                .getActiveSessions(currentUser.getId(), currentRefreshToken);
        return ResponseEntity.ok(sessions);
    }

    @Operation(
            summary = "Cerrar sesion por ID",
            description = """
                    Revoca una sesion especifica del usuario autenticado.
                    Solo el dueño de la sesion puede revocarla.
                    Útil para cerrar sesion en un dispositivo remoto desde la
                    pantalla de 'Seguridad de la cuenta'.
                    """,
            security = {
                    @SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME),
                    @SecurityRequirement(name = OpenApiConfig.COOKIE_SCHEME)
            }
    )
    @DeleteMapping("/sessions/{sessionId}")
    public ResponseEntity<MessageResponse> revokeSession(
            @Parameter(description = "ID de la sesion a revocar.")
            @PathVariable UUID sessionId,
            @Parameter(hidden = true) @AuthenticationPrincipal CustomUserPrincipal currentUser) {
        refreshTokenService.revokeSession(sessionId, currentUser.getId());
        return ResponseEntity.ok(new MessageResponse("Session revoked successfully"));
    }

    // Recuperacion de contraseña con codigo OTP
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
