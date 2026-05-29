package com.vc.auth_backend.modules.auth.repository;

import com.vc.auth_backend.modules.auth.entity.PasswordResetOtp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface PasswordResetOtpRepository extends JpaRepository<PasswordResetOtp, UUID> {
    @Query("""
            SELECT o FROM PasswordResetOtp o
            WHERE o.userId = :userId
              AND o.used   = false
              AND o.expiresAt > :now
            ORDER BY o.createdAt DESC
            LIMIT 1
            """)
    Optional<PasswordResetOtp> findActiveOtpByUserId(
            @Param("userId") UUID userId,
            @Param("now") Instant now);

    @Modifying
    @Query("""
            UPDATE PasswordResetOtp o
            SET o.used = true
            WHERE o.userId   = :userId
              AND o.used      = false
              AND o.expiresAt > :now
            """)
    void invalidateActiveOtpsByUserId(
            @Param("userId") UUID userId,
            @Param("now") Instant now);

    @Modifying
    @Query("DELETE FROM PasswordResetOtp o WHERE o.expiresAt <= :now")
    int deleteExpiredOtps(@Param("now") Instant now);
}
