package com.vc.auth_backend.modules.auth.service;

import com.vc.auth_backend.modules.auth.dto.AuthResponse;
import com.vc.auth_backend.modules.auth.dto.LoginRequest;
import com.vc.auth_backend.modules.auth.dto.RefreshTokenRequest;
import com.vc.auth_backend.modules.auth.dto.RegisterRequest;

public interface AuthenticationService {
    AuthResponse authenticate(LoginRequest request);
    AuthResponse register(RegisterRequest request);
    AuthResponse refreshToken(RefreshTokenRequest request);
}
