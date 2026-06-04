package com.vc.auth_backend.modules.auth.service;

import com.vc.auth_backend.modules.auth.dto.request.ForgotPasswordRequest;
import com.vc.auth_backend.modules.auth.dto.request.ResetPasswordRequest;
import com.vc.auth_backend.modules.auth.dto.request.VerifyOtpRequest;
import com.vc.auth_backend.modules.auth.repository.OtpRedisRepository;
import com.vc.auth_backend.modules.email.EmailProvider;
import com.vc.auth_backend.modules.email.template.OtpEmailTemplate;
import com.vc.auth_backend.modules.user.entity.User;
import com.vc.auth_backend.modules.user.repository.UserRepository;
import com.vc.auth_backend.shared.exception.InvalidOtpException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordResetService {
    private final UserRepository userRepository;
    private final OtpRedisRepository otpRedisRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final EmailProvider emailProvider;
    private final OtpEmailTemplate emailTemplate;

    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${app.otp.expiration-minutes}")
    private int otpExpirationMinutes;

    @Transactional(readOnly = true)
    public void requestPasswordReset(ForgotPasswordRequest request) {
        Optional<User> userOpt = userRepository.findByEmail(request.email());
        if (userOpt.isEmpty()) {
            log.debug("Password reset requested for unknown email: {}", request.email());
            return;
        }
        User user = userOpt.get();

        if (user.isOAuthUser()) {
            log.debug("Password reset silently skipped for OAuth user: provider={} email={}",
                    user.getProvider(), user.getEmail());
            return;
        }

        String rawCode = generateOtpCode();
        String hashedCode = passwordEncoder.encode(rawCode);
        otpRedisRepository.save(user.getId(), hashedCode);

        String htmlBody = emailTemplate.build(rawCode, otpExpirationMinutes);
        emailProvider.send(user.getEmail(), emailTemplate.subject(), htmlBody);
        log.info("Password reset OTP sent to userId={}", user.getId());
    }

    public void verifyOtp(VerifyOtpRequest request) {
        User user = findActiveLocalUserByEmail(request.email());
        validateOtp(user.getId(), request.code());
        log.debug("OTP verified (not consumed) for userId={}", user.getId());
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        User user = findActiveLocalUserByEmail(request.email());
        validateOtp(user.getId(), request.code());
        otpRedisRepository.delete(user.getId());
        // Cambiar contraseña y revocar el refresh token (sesiones activas)
        user.setPassword(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);
        refreshTokenService.logoutAll(user.getId());
        log.info("Password reset successful for userId={}. All sessions revoked.", user.getId());
    }

    // helpers
    private String generateOtpCode() {
        int code = secureRandom.nextInt(1_000_000);
        return String.format("%06d", code);
    }

    private User findActiveLocalUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .filter(User::isActive)
                .filter(User::isLocalUser) // usuarios OAuth no tienen contraseña
                .orElseThrow(() -> new InvalidOtpException("Invalid or expired code"));
    }

    /**
     * Busca el hash en Redis y lo compara con el código recibido.
     * Casos que lanzan InvalidOtpException (mismo mensaje en todos — sin hints):
     * - Key no existe en Redis (expiró o ya fue consumido)
     * - Código incorrecto (BCrypt.matches retorna false)
     */

    private void validateOtp(UUID userId, String rawCode) {
        String storedHash = otpRedisRepository.findHash(userId)
                .orElseThrow(() -> {
                    log.warn("OTP not found in Redis for userId={} (expired or consumed)", userId);
                    return new InvalidOtpException("Invalid or expired code");
                });

        if (!passwordEncoder.matches(rawCode, storedHash)) {
            log.warn("Incorrect OTP attempt for userId={}", userId);
            throw new InvalidOtpException("Invalid or expired code");
        }
    }
}
