package com.vc.auth_backend.modules.auth.service;

import com.vc.auth_backend.modules.auth.dto.AuthResponse;
import com.vc.auth_backend.modules.auth.dto.LoginRequest;
import com.vc.auth_backend.modules.auth.dto.RefreshTokenRequest;
import com.vc.auth_backend.modules.auth.dto.RegisterRequest;
import com.vc.auth_backend.modules.auth.entity.RefreshToken;
import com.vc.auth_backend.modules.auth.jwt.JwtService;
import com.vc.auth_backend.modules.auth.repository.PreAuthRedisRepository;
import com.vc.auth_backend.modules.auth.security.CustomUserPrincipal;
import com.vc.auth_backend.modules.user.entity.Role;
import com.vc.auth_backend.modules.user.entity.User;
import com.vc.auth_backend.modules.user.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthenticationService {
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final PreAuthRedisRepository  preAuthRedisRepository;

    @Override
    public AuthResponse authenticate(LoginRequest request, HttpServletRequest httpRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password()));

        CustomUserPrincipal userDetails = (CustomUserPrincipal) authentication.getPrincipal();

        assert userDetails != null;
        if (userDetails.user().isTwoFactorEnabled()) {
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
        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new DataIntegrityViolationException("Email is already registered");
        }

        User newUser = User.builder()
                .name(request.fullName())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(Role.USER)
                .active(true)
                .country("PE")
                .language("es-ES")
                .build();
        userRepository.save(newUser);

        UserDetails userDetails = new CustomUserPrincipal(newUser);
        String accessToken = jwtService.generateToken(userDetails);
        String refreshToken = refreshTokenService
                .createRefreshToken(newUser.getId(), httpRequest).getToken();

        return AuthResponse.builder()
                .token(accessToken)
                .refreshToken(refreshToken)
                .message("Register successfully")
                .build();
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
