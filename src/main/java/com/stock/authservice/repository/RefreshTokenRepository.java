package com.stock.authservice.repository;

import com.stock.authservice.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {

    // Basic queries
    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findByUserId(String userId);

    // Valid tokens
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.token = :token AND rt.isRevoked = false AND rt.expiresAt > :now")
    Optional<RefreshToken> findValidToken(@Param("token") String token, @Param("now") LocalDateTime now);

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.userId = :userId AND rt.isRevoked = false AND rt.expiresAt > :now")
    List<RefreshToken> findValidTokensByUserId(@Param("userId") String userId, @Param("now") LocalDateTime now);
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :now")
    int deleteByExpiresAtBefore(@Param("now") LocalDateTime now);
    // Revoked tokens
    List<RefreshToken> findByIsRevoked(Boolean isRevoked);

    List<RefreshToken> findByUserIdAndIsRevoked(String userId, Boolean isRevoked);

    // Expired tokens
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.expiresAt <= :now")
    List<RefreshToken> findExpiredTokens(@Param("now") LocalDateTime now);

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.userId = :userId AND rt.expiresAt <= :now")
    List<RefreshToken> findExpiredTokensByUserId(@Param("userId") String userId, @Param("now") LocalDateTime now);

    // Delete operations
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.userId = :userId")
    void deleteByUserId(@Param("userId") String userId);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt <= :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.userId = :userId AND rt.isRevoked = true")
    void deleteRevokedTokensByUserId(@Param("userId") String userId);

    // Revoke operations
    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.isRevoked = true, rt.revokedAt = :now WHERE rt.userId = :userId")
    void revokeAllUserTokens(@Param("userId") String userId, @Param("now") LocalDateTime now);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.isRevoked = true, rt.revokedAt = :now WHERE rt.token = :token")
    void revokeToken(@Param("token") String token, @Param("now") LocalDateTime now);

    // Count queries
    long countByUserId(String userId);

    long countByUserIdAndIsRevoked(String userId, Boolean isRevoked);

    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.userId = :userId AND rt.isRevoked = false AND rt.expiresAt > :now")
    long countValidTokensByUserId(@Param("userId") String userId, @Param("now") LocalDateTime now);

    // Device-based queries
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.userId = :userId AND rt.ipAddress = :ipAddress AND rt.isRevoked = false")
    List<RefreshToken> findActiveTokensByUserIdAndIp(
            @Param("userId") String userId,
            @Param("ipAddress") String ipAddress
    );

    // Cleanup old tokens
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.createdAt < :cutoffDate")
    void deleteOldTokens(@Param("cutoffDate") LocalDateTime cutoffDate);
}
