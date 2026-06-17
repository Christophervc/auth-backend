package com.vc.auth_backend.config;

import com.vc.auth_backend.config.ratelimit.RateLimitingService;
import com.vc.auth_backend.modules.auth.security.CustomUserPrincipal;
import tools.jackson.databind.json.JsonMapper;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {
    private final RateLimitingService rateLimitingService;
    private final JsonMapper jsonMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }
        String requestUri = request.getRequestURI();
        if (!requestUri.startsWith("/api/v1/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String bucketType = resolveBucketType(requestUri);
        String clientId = resolveClientId(request);

        Bucket bucket = rateLimitingService.resolveBucket(bucketType, clientId);

        if (bucket.tryConsume(1)) {
            filterChain.doFilter(request, response);
            return;
        }

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType("application/problem+json");
        response.setCharacterEncoding("UTF-8");

        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
                HttpStatus.TOO_MANY_REQUESTS, "Too many requests, please wait");
        problemDetail.setTitle("Rate Limit Exceeded");
        jsonMapper.writeValue(response.getWriter(), problemDetail);
        response.getWriter().flush();
    }

    private String resolveBucketType(String uri) {
        if (uri.startsWith("/api/v1/auth/2fa/")) {
            return "TOTP";
        }
        if (uri.startsWith("/api/v1/auth/forgot-password") ||
            uri.startsWith("/api/v1/auth/verify-otp") ||
            uri.startsWith("/api/v1/auth/reset-password")) {
            return "OTP";
        }
        if (uri.startsWith("/api/v1/auth/login") ||
            uri.startsWith("/api/v1/auth/register")) {
            return "AUTH";
        }
        return "GEN";
    }

    private String resolveClientId(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof CustomUserPrincipal userDetails) {
            return userDetails.getId().toString();
        }
        return extractClientIp(request);
    }

    private String extractClientIp(HttpServletRequest request) {
        if (request == null) return null;
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
