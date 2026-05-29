package com.vc.auth_backend.modules.email;

public interface EmailProvider {
    void send(String to, String subject, String body);
}
