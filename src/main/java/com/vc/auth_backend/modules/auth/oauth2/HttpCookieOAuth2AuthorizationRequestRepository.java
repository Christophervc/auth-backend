package com.vc.auth_backend.modules.auth.oauth2;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Component
public class HttpCookieOAuth2AuthorizationRequestRepository implements
        AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    public static final String OAUTH2_STATE_COOKIE = "OAUTH2_STATE";
    private static final int COOKIE_EXPIRE_SECONDS = 600;

    private final Cache<String, OAuth2AuthorizationRequest> authorizationRequestCache =
            Caffeine.newBuilder()
                    .expireAfterWrite(10, TimeUnit.MINUTES)
                    .maximumSize(1_000)
                    .build();

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        if (authorizationRequest == null) {
            removeAuthorizationRequest(request, response);
            return;
        }

        String state = authorizationRequest.getState();
        authorizationRequestCache.put(state, authorizationRequest);
        addStateCookie(response, state);
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return extractStateCookie(request)
                .map(authorizationRequestCache::getIfPresent)
                .orElse(null);
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        OAuth2AuthorizationRequest authRequest = loadAuthorizationRequest(request);
        extractStateCookie(request)
                .ifPresent(authorizationRequestCache::invalidate);
        clearStateCookie(response);
        return authRequest;
    }

    // cookie helpers
    private void addStateCookie(HttpServletResponse response, String state) {
        ResponseCookie cookie = ResponseCookie.from(OAUTH2_STATE_COOKIE, state)
                .httpOnly(true)
                .secure(false) // true en producción con HTTPS
                .sameSite("Lax") // el callback de Google es cross-site
                .path("/")
                .maxAge(COOKIE_EXPIRE_SECONDS)
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

    private Optional<String> extractStateCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return Optional.empty();
        return Arrays.stream(request.getCookies())
                .filter(c->OAUTH2_STATE_COOKIE.equals(c.getName()))
                .map(Cookie::getValue)
                .filter(v-> !v.isBlank())
                .findFirst();
    }

    private void clearStateCookie(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(OAUTH2_STATE_COOKIE, "")
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .maxAge(0)
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }
}
