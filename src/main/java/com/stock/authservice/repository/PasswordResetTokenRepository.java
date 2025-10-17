package com.stock.authservice.repository;

import com.stock.authservice.entity.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, String> {

    // Basic queries
    Optional<PasswordResetToken> findByToken(String token);

    List<PasswordResetToken> findByUserId(String userId);

    // Valid tokens
    @Query("SELECT prt FROM PasswordResetToken prt WHERE prt.token = :token AND prt.isUsed = false AND prt.expiresAt > :now")
    Optional<PasswordResetToken> findValidToken(@Param("token") String token, @Param("now") LocalDateTime now);

    @Query("SELECT prt FROM PasswordResetToken prt WHERE prt.userId = :userId AND prt.isUsed = false AND prt.expiresAt > :now")
    List<PasswordResetToken> findValidTokensByUserId(@Param("userId") String userId, @Param("now") LocalDateTime now);

    // Used tokens
    List<PasswordResetToken> findByIsUsed(Boolean isUsed);

    List<PasswordResetToken> findByUserIdAndIsUsed(String userId, Boolean isUsed);

    // Expired tokens
    @Query("SELECT prt FROM PasswordResetToken prt WHERE prt.expiresAt <= :now")
    List<PasswordResetToken> findExpiredTokens(@Param("now") LocalDateTime now);

    // Delete operations
    @Modifying
    @Query("DELETE FROM PasswordResetToken prt WHERE prt.userId = :userId")
    void deleteByUserId(@Param("userId") String userId);

    @Modifying
    @Query("DELETE FROM PasswordResetToken prt WHERE prt.expiresAt <= :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);

    @Modifying
    @Query("DELETE FROM PasswordResetToken prt WHERE prt.isUsed = true AND prt.usedAt < :cutoffDate")
    void deleteOldUsedTokens(@Param("cutoffDate") LocalDateTime cutoffDate);

    // Mark as used
    @Modifying
    @Query("UPDATE PasswordResetToken prt SET prt.isUsed = true, prt.usedAt = :now WHERE prt.token = :token")
    void markTokenAsUsed(@Param("token") String token, @Param("now") LocalDateTime now);

    // Check if user has pending reset request
    @Query("SELECT CASE WHEN COUNT(prt) > 0 THEN true ELSE false END " +
            "FROM PasswordResetToken prt " +
            "WHERE prt.userId = :userId " +
            "AND prt.isUsed = false " +
            "AND prt.expiresAt > :now")
    boolean userHasPendingResetRequest(@Param("userId") String userId, @Param("now") LocalDateTime now);

    // Count queries
    long countByUserId(String userId);

    @Query("SELECT COUNT(prt) FROM PasswordResetToken prt WHERE prt.userId = :userId AND prt.createdAt >= :since")
    long countResetRequestsSince(@Param("userId") String userId, @Param("since") LocalDateTime since);
}
