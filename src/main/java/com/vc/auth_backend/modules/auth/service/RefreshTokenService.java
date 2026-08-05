package com.vc.auth_backend.modules.auth.service;

import com.vc.auth_backend.modules.auth.controller.dto.response.SessionResponse;
import com.vc.auth_backend.modules.auth.repository.RefreshTokenRepository;
import com.vc.auth_backend.modules.auth.entity.RefreshToken;
import com.vc.auth_backend.modules.auth.jwt.JwtService;
import com.vc.auth_backend.modules.auth.repository.SessionRedisRepository;
import com.vc.auth_backend.modules.auth.security.CustomUserPrincipal;
import com.vc.auth_backend.modules.user.entity.User;
import com.vc.auth_backend.modules.user.repository.UserRepository;
import com.vc.auth_backend.shared.exception.InvalidExceptionToken;
import com.vc.auth_backend.shared.exception.MaxSessionsExceededException;
import com.vc.auth_backend.shared.util.UserAgentParser;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final UserAgentParser userAgentParser;
    private final SessionRedisRepository sessionRedisRepository;

    private static final int MAX_ACTIVE_SESSIONS = 4;

    @Transactional
    public RefreshToken createRefreshToken(UUID userId, HttpServletRequest request) {
        User user = findUser(userId);
        refreshTokenRepository.deleteExpiredTokensByUser(user, Instant.now()); // limpiar tokens expirados
        int activeSessions = refreshTokenRepository.countActiveSessionsByUser(user, Instant.now());
        if (activeSessions >= MAX_ACTIVE_SESSIONS) {
            throw new MaxSessionsExceededException("Maximum number of sessions allowed, log out of one of your devices");
        }
        // parser user-agent para metadatos del dispositivo
        String userAgentString = request != null
                ? request.getHeader("User-Agent")
                : null;
        UserAgentParser.DeviceInfo deviceInfo = userAgentParser.parse(userAgentString);

        String ipAddress = extractClientIp(request);

        //  generar JWT de refresh
        String tokenString = jwtService.generateRefreshToken(new CustomUserPrincipal(user));
        Instant expiryDate = jwtService.getExpirationDateFromToken(tokenString);

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(tokenString)
                .expiryDate(expiryDate)
                .revoked(false)
                .deviceName(deviceInfo.deviceName())
                .os(deviceInfo.os())
                .deviceType(deviceInfo.deviceType())
                .ipAddress(ipAddress)
                .build();
        RefreshToken saved = refreshTokenRepository.save(refreshToken);
        sessionRedisRepository.save(saved.getId(), userId, saved.getExpiryDate());
        return saved;
    }

    @Transactional
    public RefreshToken createRefreshToken(UUID userId) {
        return createRefreshToken(userId, null);
    }

    // Listar sesiones
    @Transactional(readOnly = true)
    public List<SessionResponse> getActiveSessions(UUID userId, String currentToken) {
        User user = findUser(userId);
        return refreshTokenRepository.findActiveSessionsByUser(user, Instant.now())
                .stream()
                .map(rt->toSessionResponse(rt, currentToken))
                .toList();
    }

    // Revoca una sesión por ID, validando que pertenezca al usuario autenticado.
    @Transactional
    public void revokeSession(UUID sessionId, UUID requestingUserId) {
        RefreshToken session = refreshTokenRepository.findById(sessionId)
                .orElseThrow(() -> new EntityNotFoundException("Session not found"));
        if (!session.getUser().getId().equals(requestingUserId)) {
            log.warn("User {} attempted to revoke session {} owned by {}",
                    requestingUserId, sessionId, session.getUser().getId());
            throw new AccessDeniedException("You do not have permission to revoke this session");
        }
        session.setRevoked(true);
        refreshTokenRepository.save(session);
        sessionRedisRepository.delete(sessionId);
        log.info("Session {} revoked by userId={}", sessionId, requestingUserId);
    }

    @Transactional
    public void logout(String token) {
        refreshTokenRepository.findByToken(token).ifPresent(refreshToken -> {
            refreshToken.setRevoked(true);
            refreshTokenRepository.save(refreshToken);
            sessionRedisRepository.delete(refreshToken.getId());
        });
    }

    @Transactional
    public void logoutAll(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));
        List<RefreshToken> activeSessions = refreshTokenRepository.findActiveSessionsByUser(user, Instant.now());
        refreshTokenRepository.revokeAllUserTokens(user);
        activeSessions.forEach(rt -> sessionRedisRepository.delete(rt.getId()));
        log.info("All sessions revoked for userId={} ({} sessions cleared from Redis)", userId, activeSessions.size());
    }

    @Transactional
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(token);
            throw new InvalidExceptionToken("Refresh token was expired. Please make a new sign in request");
        }
        if (token.isRevoked()) {
            throw new InvalidExceptionToken("Refresh token has been revoked. Please sign in again");
        }
        return token;
    }

    @Transactional
    public void touchLastUsedAt(String token) {
        refreshTokenRepository.updateLastUsedAt(token, Instant.now());
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    private User findUser(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));
    }

    private String extractClientIp(HttpServletRequest request) {
        if (request == null) return null;
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private SessionResponse toSessionResponse(RefreshToken rt, String currentToken) {
        boolean isCurrent = currentToken != null && currentToken.equals(rt.getToken());
        return new SessionResponse(
                rt.getId(),
                rt.getDeviceName(),
                rt.getOs(),
                rt.getDeviceType(),
                rt.getIpAddress(),
                rt.getLastUsedAt(),
                rt.getCreatedAt(),
                rt.getExpiryDate(),
                isCurrent
        );
    }
}