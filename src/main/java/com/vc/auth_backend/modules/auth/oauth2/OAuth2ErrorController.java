package com.vc.auth_backend.modules.auth.oauth2;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/oauth2")
public class OAuth2ErrorController {

    private static final Map<String, String> ERROR_MESSAGES = Map.of(
            "OAUTH2_FAILED",
            "Google authentication failed or was cancelled. Please try again.",

            "EMAIL_EXISTS_WITH_PASSWORD",
            "An account with this email already exists. " +
                    "Please log in with your email and password. " +
                    "You can link your Google account from your profile settings afterwards."
    );

    @GetMapping(value = "/error", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, String>> oauthError(
            @RequestParam(value = "error", defaultValue = "UNKNOWN") String errorCode) {

        String message = ERROR_MESSAGES.getOrDefault(
                errorCode,
                "An unexpected error occurred during OAuth2 authentication."
        );

        return ResponseEntity.badRequest().body(Map.of(
                "error", errorCode,
                "message", message,
                "hint", "In development: open http://localhost:8080/oauth2/authorization/google in your browser to retry."
        ));
    }
}