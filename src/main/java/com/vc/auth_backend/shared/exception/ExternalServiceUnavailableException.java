package com.vc.auth_backend.shared.exception;

public class ExternalServiceUnavailableException extends  RuntimeException {
    public ExternalServiceUnavailableException(String message) {
        super(message);
    }
}
