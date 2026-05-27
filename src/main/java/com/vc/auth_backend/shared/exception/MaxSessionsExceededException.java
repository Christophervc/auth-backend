package com.vc.auth_backend.shared.exception;

public class MaxSessionsExceededException extends RuntimeException {
    public MaxSessionsExceededException(String message) {
      super(message);
    }
}
