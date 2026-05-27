package com.vc.auth_backend.modules.auth.jwt;

import com.vc.auth_backend.modules.auth.service.CookieService;
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
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final JsonMapper jsonMapper;

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
            final String userEmail = jwtService.extractUsername(token);

            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
                if (jwtService.isTokenValid(token, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());

                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (ExpiredJwtException ex) {
            log.debug("Expired JWT for URI: {}", request.getRequestURI());
            sendUnauthorizedResponse(response, "Access token expired. Please refresh your session");
            return;
        } catch (JwtException ex) {
            log.warn("Invalid JWT [{}] for URI: {}", ex.getClass().getSimpleName(), request.getRequestURI());
            sendUnauthorizedResponse(response, "Invalid token");
            return;
        } catch (UsernameNotFoundException ex) {
            log.warn("User from token not found");
            sendUnauthorizedResponse(response, "Authentication failed");
            return;
        }
        filterChain.doFilter(request, response);
    }

    private void sendUnauthorizedResponse(HttpServletResponse response, String detail) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"" + detail + "\"");
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, detail);
        pd.setTitle("Authentication failed");
        jsonMapper.writeValue(response.getWriter(), pd);
    }

    private String extractToken(HttpServletRequest request) {
        // header authorization (API y mobile)
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        // http-only browser
        return cookieService.getAccessToken(request).orElse(null);
    }
}
