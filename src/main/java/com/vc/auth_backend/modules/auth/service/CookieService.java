package com.vc.auth_backend.modules.auth.service;

import com.vc.auth_backend.modules.auth.dto.AuthResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Optional;

@Service
public class CookieService {

    @Value("${jwt.time.expiration}")
    private long accessExpirationMs;

    @Value("${jwt.time.refresh-expiration}")
    private long refreshExpirationMs;

    @Value("${app.cookie.secure:true}")
    private boolean secure;

    @Value("${app.cookie.same-site:Strict}")
    private String sameSite;

    private int accessMaxAge() {
        return (int) (accessExpirationMs / 1000);
    }

    private int refreshMaxAge() {
        return (int) (refreshExpirationMs / 1000);
    }

    private static final String ACCESS_TOKEN_COOKIE  = "access_token";
    private static final String REFRESH_TOKEN_COOKIE = "refresh_token";

    // Write
    public void addAuthCookies(HttpServletResponse response, AuthResponse authResponse) {
        addCookie(response, ACCESS_TOKEN_COOKIE, authResponse.token(), accessMaxAge());
        addCookie(response, REFRESH_TOKEN_COOKIE, authResponse.refreshToken(), refreshMaxAge());
    }

    public void clearAuthCookies(HttpServletResponse response) {
        addCookie(response, ACCESS_TOKEN_COOKIE, "", 0);
        addCookie(response, REFRESH_TOKEN_COOKIE, "", 0);
    }

    // Read
    public Optional<String> getAccessToken(HttpServletRequest request) {
        return extractCookie(request, ACCESS_TOKEN_COOKIE);
    }

    public Optional<String> getRefreshToken(HttpServletRequest request) {
        return extractCookie(request, REFRESH_TOKEN_COOKIE);
    }

    private void addCookie(HttpServletResponse response,
                           String name,
                           String value,
                           int maxAge) {
        ResponseCookie cookie = ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(secure)
                .sameSite(sameSite)
                .path("/")
                .maxAge(maxAge)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private Optional<String> extractCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return Optional.empty();
        return Arrays.stream(request.getCookies())
                .filter(c -> name.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst();
    }
}
