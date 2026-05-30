package com.vc.auth_backend.shared.exception;

public class OAuth2AccountException extends RuntimeException {
    public OAuth2AccountException(String message) {
        super(message);
    }
}
