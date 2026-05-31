package com.vc.auth_backend.modules.auth.repository;

import com.vc.auth_backend.modules.auth.entity.RefreshToken;
import com.vc.auth_backend.modules.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByToken(String token);

    @Query("""
            SELECT r FROM RefreshToken r
            WHERE r.user = :user
              AND r.revoked = false
              AND r.expiryDate > :now
            ORDER BY r.lastUsedAt DESC
            """)
    List<RefreshToken> findActiveSessionsByUser(
            @Param("user") User user,
            @Param("now") Instant now);

    @Query("""
            SELECT COUNT(r) FROM RefreshToken r
            WHERE r.user = :user
              AND r.revoked = false
              AND r.expiryDate > :now
            """)
    int countActiveSessionsByUser(
            @Param("user") User user,
            @Param("now") Instant now);

    @Modifying
    @Query("""
            UPDATE RefreshToken r
            SET r.lastUsedAt = :now
            WHERE r.token = :token
            """)
    void updateLastUsedAt(
            @Param("token") String token,
            @Param("now") Instant now);

    @Modifying // update to revoked refresh token
    @Query("UPDATE RefreshToken r SET r.revoked = true WHERE r.user = :user")
    void revokeAllUserTokens(@Param("user") User user);

    @Modifying
    @Query("DELETE FROM RefreshToken r WHERE r.user = :user")
    void deleteByUser(@Param("user") User user);

    @Modifying
    @Query("DELETE FROM RefreshToken r WHERE r.user = :user AND r.expiryDate <= :now")
    void deleteExpiredTokensByUser(@Param("user") User user, @Param("now") Instant now);
}