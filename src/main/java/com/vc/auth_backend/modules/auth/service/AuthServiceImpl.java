package com.vc.auth_backend.modules.auth.service;

import com.vc.auth_backend.modules.auth.controller.dto.response.AuthResponse;
import com.vc.auth_backend.modules.auth.controller.dto.request.LoginRequest;
import com.vc.auth_backend.modules.auth.controller.dto.request.RefreshTokenRequest;
import com.vc.auth_backend.modules.auth.controller.dto.request.RegisterRequest;
import com.vc.auth_backend.modules.auth.entity.RefreshToken;
import com.vc.auth_backend.modules.auth.jwt.JwtService;
import com.vc.auth_backend.modules.auth.repository.PreAuthRedisRepository;
import com.vc.auth_backend.modules.auth.security.CustomUserPrincipal;
import com.vc.auth_backend.modules.user.entity.Role;
import com.vc.auth_backend.modules.user.entity.User;
import com.vc.auth_backend.modules.user.repository.UserRepository;
import com.vc.auth_backend.shared.exception.EmailNotVerifiedException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthenticationService {
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final PreAuthRedisRepository preAuthRedisRepository;
    private final EmailVerificationService emailVerificationService;

    @Override
    public AuthResponse authenticate(LoginRequest request, HttpServletRequest httpRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password()));

        CustomUserPrincipal userDetails = (CustomUserPrincipal) authentication.getPrincipal();
        User user = Objects.requireNonNull(userDetails).user();

        if (user.isLocalUser() && !user.isEmailVerified()) {
            throw new EmailNotVerifiedException("Please verify your email before logging in.");
        }

        if (user.isTwoFactorEnabled()) {
            String preAuthToken = UUID.randomUUID().toString();
            preAuthRedisRepository.save(preAuthToken, userDetails.getUsername());

            return AuthResponse.builder()
                    .requiresTwoFactor(true)
                    .preAuthToken(preAuthToken)
                    .message("Two-factor authentication required")
                    .build();
        }

        String accessToken = jwtService.generateToken(userDetails);
        String refreshToken = refreshTokenService
                .createRefreshToken(userDetails.getId(), httpRequest).getToken();
        return AuthResponse.builder()
                .token(accessToken)
                .refreshToken(refreshToken)
                .message("Login successfully")
                .build();
    }

    @Override
    @Transactional
    public AuthResponse register(RegisterRequest request, HttpServletRequest httpRequest) {
        if (!request.password().equals(request.confirmPassword())) {
            throw new IllegalArgumentException("Passwords do not match");
        }

        final String genericMessage = "If this email is available, we've sent you a verification code.";

        Optional<User> existingUserOpt = userRepository.findByEmail(request.email());

        if (existingUserOpt.isPresent()) {
            User existingUser = existingUserOpt.get();
            //throw new DataIntegrityViolationException("Email is already registered");
            if (existingUser.isLocalUser() && !existingUser.isEmailVerified()) {
                emailVerificationService.sendVerificationCode(existingUser);
            } else {
                log.debug("Registration attempt for an already-registered email ignored");
            }
            return AuthResponse.builder().message(genericMessage).build();
        }

        User newUser = User.builder()
                .name(request.fullName())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(Role.USER)
                .active(true)
                .country("PE")
                .language("es-ES")
                .emailVerified(false)
                .build();
        //userRepository.save(newUser);

        try {
            userRepository.saveAndFlush(newUser);
        } catch (DataIntegrityViolationException ex) {
            log.debug("Race condition on register: email was taken concurrently");
            return AuthResponse.builder().message(genericMessage).build();
        }

        emailVerificationService.sendVerificationCode(newUser);
        return AuthResponse.builder().message(genericMessage).build();
        /*
        UserDetails userDetails = new CustomUserPrincipal(newUser);
        String accessToken = jwtService.generateToken(userDetails);
        String refreshToken = refreshTokenService
                .createRefreshToken(newUser.getId(), httpRequest).getToken();

        return AuthResponse.builder()
                .token(accessToken)
                .refreshToken(refreshToken)
                .message("Register successfully")
                .build();

         */
    }

    @Override
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        String requestRefreshToken = request.refreshToken();
        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                            refreshTokenService.touchLastUsedAt(requestRefreshToken);
                            refreshTokenService.logout(requestRefreshToken);
                            CustomUserPrincipal userDetails = new CustomUserPrincipal(user);
                            String newAccessToken = jwtService.generateToken(userDetails);
                            String newRefreshToken = refreshTokenService
                                    .createRefreshToken(user.getId()).getToken();

                            return AuthResponse.builder()
                                    .token(newAccessToken)
                                    .message("Token refreshed successfully")
                                    .refreshToken(newRefreshToken)
                                    .build();
                        }
                ).orElseThrow(() -> new RuntimeException("Refresh token is not in database!"));
    }
}
