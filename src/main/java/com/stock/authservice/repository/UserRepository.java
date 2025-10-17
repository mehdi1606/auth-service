package com.stock.authservice.repository;

import com.stock.authservice.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {

    // Basic queries
    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);
    Optional<User> findByPasswordResetToken(String token);
    Optional<User> findByEmailVerificationToken(String token);
    Optional<User> findByUsernameOrEmail(String username, String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    boolean existsByPhoneNumber(String phoneNumber);

    // Active users
    List<User> findByIsActive(Boolean isActive);

    Optional<User> findByUsernameAndIsActive(String username, Boolean isActive);

    Optional<User> findByEmailAndIsActive(String email, Boolean isActive);

    // Locked accounts
    @Query("SELECT u FROM User u WHERE u.lockedUntil IS NOT NULL AND u.lockedUntil > :now")
    List<User> findLockedAccounts(@Param("now") LocalDateTime now);

    @Query("SELECT u FROM User u WHERE u.lockedUntil IS NOT NULL AND u.lockedUntil <= :now")
    List<User> findExpiredLocks(@Param("now") LocalDateTime now);

    // Failed login attempts
    @Query("SELECT u FROM User u WHERE u.failedLoginAttempts >= :threshold AND u.isActive = true")
    List<User> findUsersWithFailedAttempts(@Param("threshold") Integer threshold);

    // MFA enabled users
    List<User> findByMfaEnabled(Boolean mfaEnabled);

    // Email verification
    List<User> findByIsEmailVerified(Boolean isEmailVerified);

    @Query("SELECT u FROM User u WHERE u.isEmailVerified = false AND u.createdAt < :cutoffDate")
    List<User> findUnverifiedUsersOlderThan(@Param("cutoffDate") LocalDateTime cutoffDate);

    // Role-based queries
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = :roleName")
    List<User> findByRoleName(@Param("roleName") String roleName);

    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.id = :roleId")
    List<User> findByRoleId(@Param("roleId") String roleId);

    // Last login queries
    @Query("SELECT u FROM User u WHERE u.lastLogin IS NULL")
    List<User> findUsersWhoNeverLoggedIn();

    @Query("SELECT u FROM User u WHERE u.lastLogin < :date")
    List<User> findInactiveUsersSince(@Param("date") LocalDateTime date);

    // Password change queries
    @Query("SELECT u FROM User u WHERE u.passwordChangedAt IS NULL OR u.passwordChangedAt < :date")
    List<User> findUsersWithOldPasswords(@Param("date") LocalDateTime date);

    // Search queries
    @Query("SELECT u FROM User u WHERE " +
            "LOWER(u.username) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
            "LOWER(u.email) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
            "LOWER(u.firstName) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
            "LOWER(u.lastName) LIKE LOWER(CONCAT('%', :search, '%'))")
    Page<User> searchUsers(@Param("search") String search, Pageable pageable);

    // Count queries
    long countByIsActive(Boolean isActive);

    long countByMfaEnabled(Boolean mfaEnabled);

    @Query("SELECT COUNT(u) FROM User u WHERE u.lockedUntil IS NOT NULL AND u.lockedUntil > :now")
    long countLockedAccounts(@Param("now") LocalDateTime now);

    // Statistics
    @Query("SELECT COUNT(u) FROM User u WHERE u.createdAt >= :startDate AND u.createdAt <= :endDate")
    long countUsersCreatedBetween(
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate
    );

    @Query("SELECT COUNT(DISTINCT u) FROM User u WHERE u.lastLogin >= :startDate AND u.lastLogin <= :endDate")
    long countActiveUsersBetween(
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate
    );
}
