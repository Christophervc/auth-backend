package com.vc.auth_backend.modules.auth.oauth2;

public interface OAuth2UserInfo {
    String getId();

    String getEmail();

    String getFirstName();

    String getLastName();

    String getAvatarUrl();
}
