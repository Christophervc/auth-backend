package com.vc.auth_backend.modules.auth.service;

import com.vc.auth_backend.modules.auth.repository.RefreshTokenRepository;
import com.vc.auth_backend.modules.auth.entity.RefreshToken;
import com.vc.auth_backend.modules.auth.jwt.JwtService;
import com.vc.auth_backend.modules.auth.security.CustomUserPrincipal;
import com.vc.auth_backend.modules.user.entity.User;
import com.vc.auth_backend.modules.user.repository.UserRepository;
import com.vc.auth_backend.shared.exception.InvalidExceptionToken;
import com.vc.auth_backend.shared.exception.MaxSessionsExceededException;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    private static final int MAX_ACTIVE_SESSIONS = 4;

    @Transactional
    public RefreshToken createRefreshToken(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));
        refreshTokenRepository.deleteExpiredTokensByUser(user, Instant.now());
        int activeSessions = refreshTokenRepository.countActiveSessionsByUser(user, Instant.now());
        if (activeSessions >= MAX_ACTIVE_SESSIONS) {
            throw new MaxSessionsExceededException("Maximum number of sessions allowed, log out of one of your devices");
        }
        //  Generar el JWT específico de Refresh que dura 7 días
        String tokenString = jwtService.generateRefreshToken(new CustomUserPrincipal(user));
        Instant expiryDate = jwtService.getExpirationDateFromToken(tokenString);

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(tokenString)
                .expiryDate(expiryDate)
                .revoked(false)
                .build();
        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    public void logout(String token) {
        refreshTokenRepository.findByToken(token).ifPresent(refreshToken -> {
            refreshToken.setRevoked(true);
            refreshTokenRepository.save(refreshToken);
        });
    }

    @Transactional
    public void logoutAll(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));
        refreshTokenRepository.revokeAllUserTokens(user);
    }

    @Transactional
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new InvalidExceptionToken("Refresh token was expired. Please make a new sign in request");
        }
        if (token.isRevoked()) {
            throw new InvalidExceptionToken("Refresh token has been revoked. Please sign in again");
        }
        return token;
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }
}