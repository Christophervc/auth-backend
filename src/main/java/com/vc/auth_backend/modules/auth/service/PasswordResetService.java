package com.vc.auth_backend.modules.auth.service;

import com.vc.auth_backend.modules.auth.dto.ForgotPasswordRequest;
import com.vc.auth_backend.modules.auth.dto.ResetPasswordRequest;
import com.vc.auth_backend.modules.auth.dto.VerifyOtpRequest;
import com.vc.auth_backend.modules.auth.entity.PasswordResetOtp;
import com.vc.auth_backend.modules.auth.repository.PasswordResetOtpRepository;
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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor

public class PasswordResetService {
    private final UserRepository userRepository;
    private final PasswordResetOtpRepository otpRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService       refreshTokenService;
    private final EmailProvider emailProvider;
    private final OtpEmailTemplate emailTemplate;

    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${app.otp.expiration-minutes}")
    private int otpExpirationMinutes;

    @Transactional
    public void requestPasswordReset(ForgotPasswordRequest request){
        Optional<User> userOpt = userRepository.findByEmail(request.email());
        if (userOpt.isEmpty()) {
            log.debug("Password reset requested for unknown email: {}", request.email());
            return;
        }
        User user = userOpt.get();
        otpRepository.invalidateActiveOtpsByUserId(user.getId(), Instant.now());

        String rawCode   = generateOtpCode();
        String hashedCode = passwordEncoder.encode(rawCode);

        PasswordResetOtp otp = PasswordResetOtp.builder()
                .userId(user.getId())
                .codeHash(hashedCode)
                .expiresAt(Instant.now().plus(otpExpirationMinutes, ChronoUnit.MINUTES))
                .used(false)
                .build();
        otpRepository.save(otp);

        String htmlBody = emailTemplate.build(rawCode, otpExpirationMinutes);
        emailProvider.send(user.getEmail(), emailTemplate.subject(), htmlBody);
        log.info("Password reset OTP sent to userId={}", user.getId());
    }

    @Transactional(readOnly = true)
    public void verifyOtp(VerifyOtpRequest request){
        User user = findActiveUserByEmail(request.email());
        loadAndValidateOtp(user.getId(), request.code());
        log.debug("OTP verified (not consumed) for userId={}", user.getId());
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request){
        User user = findActiveUserByEmail(request.email());
        PasswordResetOtp otp = loadAndValidateOtp(user.getId(), request.code());
        otp.setUsed(true);
        otpRepository.save(otp);
        // Cambiar contraseña  y revocar el refresh token (sesiones activas)
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

    private User findActiveUserByEmail(String email){
        return userRepository.findByEmail(email)
                .filter(User::isActive)
                .orElseThrow(()-> new InvalidOtpException("Invalid or expired code"));
    }

    private PasswordResetOtp loadAndValidateOtp(UUID userId, String rawCode){
        PasswordResetOtp otp = otpRepository
                .findActiveOtpByUserId(userId, Instant.now())
                .orElseThrow(() -> new InvalidOtpException("Invalid or expired code"));
        if (!passwordEncoder.matches(rawCode, otp.getCodeHash())) {
            log.warn("Incorrect OTP attempt for userId={}", userId);
            throw new InvalidOtpException("Invalid or expired code");
        }
        return otp;
    }
}
