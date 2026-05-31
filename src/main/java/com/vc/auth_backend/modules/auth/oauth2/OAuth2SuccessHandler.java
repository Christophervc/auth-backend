package com.vc.auth_backend.modules.auth.oauth2;

import com.vc.auth_backend.modules.auth.dto.AuthResponse;
import com.vc.auth_backend.modules.auth.jwt.JwtService;
import com.vc.auth_backend.modules.auth.security.CustomUserPrincipal;
import com.vc.auth_backend.modules.auth.service.CookieService;
import com.vc.auth_backend.modules.auth.service.RefreshTokenService;
import com.vc.auth_backend.modules.user.entity.Role;
import com.vc.auth_backend.modules.user.entity.User;
import com.vc.auth_backend.modules.user.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final CookieService cookieService;

    @Value("${app.oauth2.redirect-uri.success}")
    private String successRedirectUri;

    @Value("${app.oauth2.redirect-uri.failure}")
    private String failureRedirectUri;

    @Override
    @Transactional
    public void onAuthenticationSuccess(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull Authentication authentication) throws IOException {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        String registrationId = oauthToken.getAuthorizedClientRegistrationId(); // "google"

        // Normalizar los atributos del proveedor a nuestro contrato interno
        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
                registrationId, oauthToken.getPrincipal().getAttributes());

        log.debug("OAuth2 success: provider={} email={}", registrationId, userInfo.getEmail());

        processOAuthLogin(request, response, userInfo, registrationId);
    }

    private void processOAuthLogin(
            HttpServletRequest request,
            HttpServletResponse response,
            OAuth2UserInfo userInfo,
            String registrationId) throws IOException {

        // ya existe una cuenta OAuth con este proveedor e ID
        Optional<User> existingOAuthUser =
                userRepository.findByProviderAndProviderId(registrationId, userInfo.getId());

        if (existingOAuthUser.isPresent()) {
            User user = existingOAuthUser.get();
            syncProfileFromProvider(user, userInfo); // actualiza nombre/avatar si cambiaron
            issueTokensAndRedirect(request, response, user);
            return;
        }

        // el email ya existe pero es cuenta local
        Optional<User> existingLocalUser = userRepository.findByEmail(userInfo.getEmail());
        if (existingLocalUser.isPresent()) {
            log.warn("OAuth2 email conflict: email={} already registered as local account",
                    userInfo.getEmail());
            invalidateSession(request);
            redirectWithError(response, "EMAIL_EXISTS_WITH_PASSWORD");
            return;
        }

        // usuario completamente nuevo → crear cuenta
        User newUser = createOAuthUser(userInfo, registrationId);
        log.info("New user registered via OAuth2: provider={} userId={}", registrationId, newUser.getId());
        issueTokensAndRedirect(request, response, newUser);
    }

    private void syncProfileFromProvider(User user, OAuth2UserInfo userInfo) {
        boolean changed = false;

        if (userInfo.getFirstName() != null && !userInfo.getFirstName().equals(user.getName())) {
            user.setName(userInfo.getFirstName());
            changed = true;
        }
        if (userInfo.getLastName() != null && !userInfo.getLastName().equals(user.getLastname())) {
            user.setLastname(userInfo.getLastName());
            changed = true;
        }
        if (userInfo.getAvatarUrl() != null && !userInfo.getAvatarUrl().equals(user.getAvatar())) {
            user.setAvatar(userInfo.getAvatarUrl());
            changed = true;
        }

        if (changed) {
            userRepository.save(user);
        }
    }

    private User createOAuthUser(OAuth2UserInfo userInfo, String provider) {
        User user = User.builder()
                .email(userInfo.getEmail())
                .name(userInfo.getFirstName() != null ? userInfo.getFirstName() : userInfo.getEmail())
                .lastname(userInfo.getLastName())
                .password(null)        // OAuth users have no password
                .role(Role.USER)
                .active(true)
                .provider(provider)    // "google"
                .providerId(userInfo.getId()) // Google's "sub"
                .avatar(userInfo.getAvatarUrl())
                .country("PE")
                .language("es-ES")
                .build();
        return userRepository.save(user);
    }

    private void issueTokensAndRedirect(
            HttpServletRequest request,
            HttpServletResponse response,
            User user) throws IOException {

        CustomUserPrincipal principal = new CustomUserPrincipal(user);
        String accessToken = jwtService.generateToken(principal);
        // pasar request para capturar user-agent del browser que hizo oauth2
        String refreshToken = refreshTokenService.createRefreshToken(user.getId(), request).getToken();

        AuthResponse authResponse = AuthResponse.builder()
                .token(accessToken)
                .refreshToken(refreshToken)
                .message("OAuth2 login successful")
                .build();
        // Las cookies http-only quedan seteadas en el browser.
        // El frontend no necesita leer el token de la URL — lo recibirá
        // automáticamente en cada request a través de las cookies.
        cookieService.addAuthCookies(response, authResponse);
        invalidateSession(request); // limpiar sesión OAuth2 tras emitir JWT
        log.info("OAuth2 tokens issued for userId={}", user.getId());
        getRedirectStrategy().sendRedirect(request, response, successRedirectUri);
    }

    private void invalidateSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
            log.debug("OAuth2 session invalidated");
        }
    }

    private void redirectWithError(HttpServletResponse response, String errorCode) throws IOException {
        String redirectUrl = UriComponentsBuilder
                .fromUriString(failureRedirectUri)
                .queryParam("error", errorCode)
                .build()
                .toUriString();
        response.sendRedirect(redirectUrl);
    }
}
