package com.vc.auth_backend.modules.auth.service;

import com.vc.auth_backend.modules.auth.controller.dto.response.AuthResponse;
import com.vc.auth_backend.modules.auth.controller.dto.response.ConfirmSetupResponse;
import com.vc.auth_backend.modules.auth.controller.dto.response.SetupResponse;
import com.vc.auth_backend.modules.auth.jwt.JwtService;
import com.vc.auth_backend.modules.auth.repository.PreAuthRedisRepository;
import com.vc.auth_backend.modules.auth.repository.UsedTotpCodeRedisRepository;
import com.vc.auth_backend.modules.auth.security.CustomUserPrincipal;
import com.vc.auth_backend.modules.user.entity.User;
import com.vc.auth_backend.modules.user.repository.UserRepository;
import com.vc.auth_backend.shared.exception.InvalidExceptionToken;
import com.vc.auth_backend.shared.exception.InvalidOtpException;
import dev.samstevens.totp.qr.QrData;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class TwoFactorService {
    private final UserRepository userRepository;
    private final TotpService totpService;
    private final BackupCodeService backupCodeService;
    private final RefreshTokenService refreshTokenService;
    private final PreAuthRedisRepository  preAuthRedisRepository;
    private final JwtService jwtService;
    private final UsedTotpCodeRedisRepository usedTotpCodeRedisRepository;

    @Transactional
    public SetupResponse setup(UUID userId) {
        User user = getUser(userId);
        if (user.isTwoFactorEnabled()) {
            throw new IllegalStateException("2FA is already enabled");
        }

        String secret = totpService.generateSecret();
        // Guardamos el secreto pero NO habilitamos 2FA aún
        user.setTwoFactorSecret(secret);
        userRepository.save(user);

        QrData qrData = totpService.generateQrData(user.getEmail(), secret);
        byte[] qrPng = totpService.generateQrPng(qrData);
        String base64Image = "data:image/png;base64," + Base64.getEncoder().encodeToString(qrPng);

        return new SetupResponse(secret, qrData.getUri(), base64Image);
    }

    @Transactional
    public ConfirmSetupResponse confirmSetup(UUID userId, String code) {
        User user = getUser(userId);
        if (user.isTwoFactorEnabled()) {
            throw new IllegalStateException("2FA is already enabled");
        }
        if (user.getTwoFactorSecret() == null) {
            throw new IllegalStateException("No pending 2FA setup found. Call /setup first.");
        }

        if (!totpService.verifyCode(user.getTwoFactorSecret(), code)) {
            throw new InvalidOtpException("Invalid TOTP code");
        }

        // Anti-replay: evita que el mismo código active el 2FA dos veces en rápida sucesión
        if (!usedTotpCodeRedisRepository.markAsUsedIfNew(userId, code, totpService.getPeriod())) {
            throw new InvalidOtpException("Code already used. Please wait for a new code.");
        }

        BackupCodeService.BackupCodePair codes = backupCodeService.generateBackupCodes();
        user.setTwoFactorEnabled(true);
        user.setBackupCodesJson(backupCodeService.serialize(codes.hashed()));
        userRepository.save(user);

        // Retornamos los códigos planos por única vez
        return new ConfirmSetupResponse(codes.plain());
    }

    @Transactional
    public AuthResponse verifyLogin(String preAuthToken, String code, HttpServletRequest httpRequest) {
        if (preAuthToken == null || preAuthToken.isBlank()) {
            throw new InvalidExceptionToken("Invalid or missing pre-auth token");
        }

        String email = preAuthRedisRepository.findEmailByToken(preAuthToken)
                .orElseThrow(()->new InvalidExceptionToken("Invalid or expired pre-auth token"));

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        if (!user.isTwoFactorEnabled()) {
            throw new IllegalStateException("2FA is not enabled for this user");
        }

        // 1. Intentar validar como TOTP
        boolean isValidTotp = totpService.verifyCode(user.getTwoFactorSecret(), code);

        // 2. Anti-replay: si el código TOTP es válido, verificar que no haya sido usado antes.
        //    Se hace ANTES de destruir el preAuthToken para no consumirlo en un replay.
        if (isValidTotp) {
            boolean isFirstUse = usedTotpCodeRedisRepository
                    .markAsUsedIfNew(user.getId(), code, totpService.getPeriod());
            if (!isFirstUse) {
                // El código es matemáticamente válido, pero ya fue usado: replay detectado.
                throw new InvalidOtpException("Code already used. Please wait for a new code from your authenticator app.");
            }
        }

        // 3. Si falla TOTP, intentar como Backup Code (ya consume el código en BD: sin replay posible)
        boolean isValidBackup = false;
        if (!isValidTotp) {
            isValidBackup = backupCodeService.consumeBackupCode(user, code);
        }

        if (!isValidTotp && !isValidBackup) {
            throw new InvalidOtpException("Invalid 2FA code");
        }

        if (isValidBackup) {
            userRepository.save(user); // Guarda la nueva lista de backup codes
        }

        preAuthRedisRepository.delete(preAuthToken);

        // 4. Emitir tokens finales
        CustomUserPrincipal principal = new CustomUserPrincipal(user);
        String accessToken = jwtService.generateToken(principal);
        String refreshToken = refreshTokenService.createRefreshToken(user.getId(), httpRequest).getToken();

        return AuthResponse.builder()
                .token(accessToken)
                .refreshToken(refreshToken)
                .requiresTwoFactor(false)
                .message("Login successfully completed")
                .build();
    }

    @Transactional
    public void disable(UUID userId, String code) {
        User user = getUser(userId);
        if (!user.isTwoFactorEnabled()) {
            throw new IllegalStateException("2FA is not enabled");
        }
        if (!totpService.verifyCode(user.getTwoFactorSecret(), code)) {
            throw new InvalidOtpException("Invalid TOTP code");
        }

        user.setTwoFactorEnabled(false);
        user.setTwoFactorSecret(null);
        user.setBackupCodesJson(null);
        userRepository.save(user);
        // revocar sesiones activas para obligar a iniciar sesión normal
        refreshTokenService.logoutAll(user.getId());
    }

    private User getUser(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));
    }
}
