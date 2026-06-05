package com.vc.auth_backend.modules.auth.service;

import com.vc.auth_backend.modules.auth.controller.dto.response.AuthResponse;
import com.vc.auth_backend.modules.auth.controller.dto.request.LoginRequest;
import com.vc.auth_backend.modules.auth.controller.dto.request.RefreshTokenRequest;
import com.vc.auth_backend.modules.auth.controller.dto.request.RegisterRequest;
import jakarta.servlet.http.HttpServletRequest;

public interface AuthenticationService {
    AuthResponse authenticate(LoginRequest request, HttpServletRequest httpRequest);
    AuthResponse register(RegisterRequest request, HttpServletRequest httpRequest);
    AuthResponse refreshToken(RefreshTokenRequest request);
}
