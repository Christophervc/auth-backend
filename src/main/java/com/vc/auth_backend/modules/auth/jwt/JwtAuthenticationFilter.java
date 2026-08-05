package com.vc.auth_backend.modules.auth.jwt;

import com.vc.auth_backend.modules.auth.repository.SessionRedisRepository;
import com.vc.auth_backend.modules.auth.security.CustomUserPrincipal;
import com.vc.auth_backend.modules.auth.service.CookieService;
import com.vc.auth_backend.modules.user.entity.Role;
import com.vc.auth_backend.modules.user.entity.User;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final CookieService cookieService;
    private final JsonMapper jsonMapper;
    private final SessionRedisRepository sessionRedisRepository;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        try {
            final String token = extractToken(request);
            if (token == null) {
                filterChain.doFilter(request, response);
                return;
            }

            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                authenticateFromToken(token, request);
            }

        } catch (ExpiredJwtException ex) {
            log.debug("Expired JWT for URI: {}", request.getRequestURI());
            sendUnauthorizedResponse(response, "Access token expired. Please refresh your session");
            return;
        } catch (JwtException ex) {
            log.warn("Invalid JWT [{}] for URI: {}", ex.getClass().getSimpleName(), request.getRequestURI());
            sendUnauthorizedResponse(response, "Invalid token");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void authenticateFromToken(String token, HttpServletRequest request) {
        String  email  = jwtService.extractUsername(token);
        String  role   = jwtService.extractClaim(token, c -> c.get(JwtService.CLAIM_ROLE,   String.class));
        Boolean active = jwtService.extractClaim(token, c -> c.get(JwtService.CLAIM_ACTIVE, Boolean.class));
        String  uid    = jwtService.extractClaim(token, c -> c.get(JwtService.CLAIM_UID,    String.class));
        String  sid    = jwtService.extractClaim(token, c -> c.get(JwtService.CLAIM_SID,    String.class));

        if (email == null || role == null || active == null || uid == null || sid == null) {
            log.warn("JWT without required claims (role/active/uid/sid). The token may be out of date.");
            return; // Pasa como anónimo → 401 del AuthorizationFilter si el endpoint lo requiere
        }

        if (!active) {
            log.debug("JWT con claim active=false for email={}", email);
            return; // Pasa como anónimo → 401 del AuthorizationFilter si el endpoint lo requiere
        }

        if (!sessionRedisRepository.exists(UUID.fromString(sid))) {
            log.debug("JWT with sid={} not found in Redis (session revoked or expired)", sid);
            return; // Pasa como anónimo → 401. Esto es lo que cierra la ventana de revocación.
        }

        Role roleEnum = Role.valueOf(role.replace("ROLE_", ""));
        User userStub = User.builder()
                .id(UUID.fromString(uid))
                .email(email)
                .role(roleEnum)
                .active(true)
                .build();

        CustomUserPrincipal principal = new CustomUserPrincipal(userStub);
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }

    private void sendUnauthorizedResponse(HttpServletResponse response, String detail) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setHeader("WWW-Authenticate",
                "Bearer error=\"invalid_token\", error_description=\"" + detail + "\"");
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, detail);
        pd.setTitle("Authentication failed");
        jsonMapper.writeValue(response.getWriter(), pd);
    }

    private String extractToken(HttpServletRequest request) {
        // Header Authorization: Bearer <token> (API / mobile)
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        // Cookie HTTP-Only (browser)
        return cookieService.getAccessToken(request).orElse(null);
    }
}
