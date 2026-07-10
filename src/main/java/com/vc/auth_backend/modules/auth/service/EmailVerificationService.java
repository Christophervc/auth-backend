package com.vc.auth_backend.modules.auth.service;

import com.vc.auth_backend.modules.auth.controller.dto.request.ResendVerificationRequest;
import com.vc.auth_backend.modules.auth.controller.dto.request.VerifyEmailRequest;
import com.vc.auth_backend.modules.auth.repository.EmailVerificationRedisRepository;
import com.vc.auth_backend.modules.email.EmailProvider;
import com.vc.auth_backend.modules.email.template.EmailVerificationTemplate;
import com.vc.auth_backend.modules.user.entity.User;
import com.vc.auth_backend.modules.user.repository.UserRepository;
import com.vc.auth_backend.shared.exception.InvalidOtpException;
import com.vc.auth_backend.shared.util.OtpCodeGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailVerificationService {
    private final UserRepository userRepository;
    private final EmailVerificationRedisRepository verificationRedisRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailProvider emailProvider;
    private final EmailVerificationTemplate emailTemplate;
    private final OtpCodeGenerator otpCodeGenerator;
    private final Environment environment;

    @Value("${app.email-verification.expiration-minutes}")
    private int expirationMinutes;

    public void sendVerificationCode(User user) {
        String rawCode = otpCodeGenerator.generate();
        String hashedCode = passwordEncoder.encode(rawCode);
        verificationRedisRepository.save(user.getId(), hashedCode);

        String htmlBody = emailTemplate.build(rawCode, expirationMinutes);
        emailProvider.send(user.getEmail(), emailTemplate.subject(), htmlBody);

        log.info("Email verification code sent to userId={}", user.getId());
        // logs dev-only
        if (environment.matchesProfiles("dev")) {
            log.warn("[DEV-ONLY] Verification code for userId={} email={} -> {}",
                    user.getId(), user.getEmail(), rawCode);
        }
    }

    @Transactional(readOnly = true)
    public void resendVerification(ResendVerificationRequest request) {
        Optional<User> userOpt = userRepository.findByEmail(request.email());
        if (userOpt.isEmpty()) {
            log.debug("Verification resend requested for unknown email");
            return;
        }
        User user = userOpt.get();

        if (user.isOAuthUser() || user.isEmailVerified()) {
            log.debug("Verification resend silently skipped: userId={} oauth={} verified={}",
                    user.getId(), user.isOAuthUser(), user.isEmailVerified());
            return;
        }

        sendVerificationCode(user);
    }

    @Transactional
    public void verifyEmail(VerifyEmailRequest request) {
        User user = userRepository.findByEmail(request.email())
                .filter(User::isActive)
                .filter(User::isLocalUser)
                .orElseThrow(() -> new InvalidOtpException("Invalid or expired code"));

        if (user.isEmailVerified()) {
            log.debug("Email already verified for userId={}", user.getId());
            return;
        }

        String storedHash = verificationRedisRepository.findHash(user.getId())
                .orElseThrow(() -> {
                    log.warn("Verification code not found in Redis for userId={} (expired or consumed)", user.getId());
                    return new InvalidOtpException("Invalid or expired code");
                });

        if (!passwordEncoder.matches(request.code(), storedHash)) {
            log.warn("Incorrect email verification code attempt for userId={}", user.getId());
            throw new InvalidOtpException("Invalid or expired code");
        }

        verificationRedisRepository.delete(user.getId());
        user.setEmailVerified(true);
        userRepository.save(user);
        log.info("Email verified successfully for userId={}", user.getId());
    }

}
