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

        boolean isAuthRequest = requestUri.startsWith("/api/v1/auth/login") || requestUri.startsWith("/api/v1/auth/register");

        String clientId = resolveClientId(request);
        String bucketKey = (isAuthRequest? "AUTH:" : "GEN:") + clientId;

        Bucket bucket = rateLimitingService.resolveBucket(bucketKey, isAuthRequest);

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
        response.getWriter().write(jsonMapper.writeValueAsString(problemDetail));
        response.getWriter().flush();
    }

    private String resolveClientId(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof CustomUserPrincipal userDetails) {
            return userDetails.getId().toString();
        }
        return request.getRemoteAddr();
    }
}
