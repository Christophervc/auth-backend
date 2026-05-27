package com.vc.auth_backend.shared.exception;

public class InvalidExceptionToken extends RuntimeException {
    public InvalidExceptionToken(String message) {
        super(message);
    }
}
