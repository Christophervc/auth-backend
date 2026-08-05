package com.vc.auth_backend.shared.util;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;

@Component
public class OtpCodeGenerator {
    private final SecureRandom random = new SecureRandom();

    public String generate(){
        int code = random.nextInt(1_000_000);
        return String.format("%06d", code);
    }
}
