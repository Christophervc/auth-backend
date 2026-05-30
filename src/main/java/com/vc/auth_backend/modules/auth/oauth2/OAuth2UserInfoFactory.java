package com.vc.auth_backend.modules.auth.oauth2;

import java.util.Map;

public class OAuth2UserInfoFactory {
    private OAuth2UserInfoFactory() {}

    public static OAuth2UserInfo getOAuth2UserInfo(
            String registrationId,
            Map<String, Object> attributes) {

        return switch (registrationId.toLowerCase()) {

            case "google" -> new GoogleOAuth2UserInfo(attributes);
            // case "github"   -> new GithubOAuth2UserInfo(attributes);
            // case "facebook" -> new FacebookOAuth2UserInfo(attributes);
            default -> throw new IllegalArgumentException(
                    "OAuth2 provider not supported: " + registrationId +
                            ". Supported providers: google");
        };
    }
}
