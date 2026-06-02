package com.vc.auth_backend.modules.user.entity;

import com.vc.auth_backend.shared.util.AesEncryptedStringConverter;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

@Entity
@Table(name = "users",
        uniqueConstraints = {
                @UniqueConstraint(
                        name  = "uk_users_provider_provider_id",
                        columnNames = {"provider", "provider_id"}
                )
        })
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column
    private String password;

    @Column(nullable = false)
    private String name;

    @Column(length = 80)
    private String lastname;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @Column(nullable = false)
    private boolean active = true;

    @Column()
    private String avatar;

    @Column(length = 20)
    private String phone;

    @Column(length = 5)
    private String country = "PE";

    @Column(length = 5)
    private String language = "es-ES";

    @Column(nullable = false)
    private LocalDateTime joinedAt;

    // oauth
    @Builder.Default
    @Column(nullable = false, length = 20)
    private String provider = "local";

    @Column(name = "provider_id")
    private String providerId;

    public boolean isLocalUser() {
        return "local".equals(this.provider);
    }

    public boolean isOAuthUser() {
        return !isLocalUser();
    }

    // 2FA
    @Column(name = "two_factor_enabled", nullable = false)
    @Builder.Default
    private boolean twoFactorEnabled = false;

    @Column(name = "two_factor_secret", length = 512)
    @Convert(converter = AesEncryptedStringConverter.class)
    private String twoFactorSecret;

    @Column(name = "backup_codes", columnDefinition = "TEXT")
    @Convert(converter = AesEncryptedStringConverter.class)
    private String backupCodesJson; // JSON array de hashes BCrypt

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User user)) return false;
        return id != null && id.equals(user.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }

    @PrePersist
    protected void onCreate() {
        this.joinedAt = LocalDateTime.now(ZoneOffset.UTC);
    }
}
