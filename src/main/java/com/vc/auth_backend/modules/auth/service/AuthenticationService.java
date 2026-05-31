package com.vc.auth_backend.modules.auth.service;

import com.vc.auth_backend.modules.auth.dto.AuthResponse;
import com.vc.auth_backend.modules.auth.dto.LoginRequest;
import com.vc.auth_backend.modules.auth.dto.RefreshTokenRequest;
import com.vc.auth_backend.modules.auth.dto.RegisterRequest;
import jakarta.servlet.http.HttpServletRequest;

public interface AuthenticationService {
    AuthResponse authenticate(LoginRequest request, HttpServletRequest httpRequest);
    AuthResponse register(RegisterRequest request, HttpServletRequest httpRequest);
    AuthResponse refreshToken(RefreshTokenRequest request);
}
