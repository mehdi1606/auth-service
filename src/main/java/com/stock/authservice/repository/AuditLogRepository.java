package com.stock.authservice.repository;

import com.stock.authservice.entity.AuditLog;
import com.stock.authservice.entity.AuditLog.EventType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, String> {

  // Basic queries
  List<AuditLog> findByUserId(String userId);

  Page<AuditLog> findByUserId(String userId, Pageable pageable);

  List<AuditLog> findByUsername(String username);

  Page<AuditLog> findByUsername(String username, Pageable pageable);

  // Event type queries
  List<AuditLog> findByEventType(EventType eventType);

  Page<AuditLog> findByEventType(EventType eventType, Pageable pageable);

  List<AuditLog> findByEventTypeIn(List<EventType> eventTypes);

  // Success/Failure queries
  List<AuditLog> findBySuccess(Boolean success);

  Page<AuditLog> findBySuccess(Boolean success, Pageable pageable);

  List<AuditLog> findByUserIdAndSuccess(String userId, Boolean success);

  List<AuditLog> findByEventTypeAndSuccess(EventType eventType, Boolean success);

  // Time-based queries
  List<AuditLog> findByTimestampBetween(LocalDateTime start, LocalDateTime end);

  Page<AuditLog> findByTimestampBetween(LocalDateTime start, LocalDateTime end, Pageable pageable);

  @Query("SELECT al FROM AuditLog al WHERE al.userId = :userId AND al.timestamp >= :since")
  List<AuditLog> findByUserIdSince(@Param("userId") String userId, @Param("since") LocalDateTime since);

  // IP Address queries
  List<AuditLog> findByIpAddress(String ipAddress);

  @Query("SELECT al FROM AuditLog al WHERE al.userId = :userId AND al.ipAddress = :ipAddress")
  List<AuditLog> findByUserIdAndIpAddress(@Param("userId") String userId, @Param("ipAddress") String ipAddress);

  // Complex queries
  @Query("SELECT al FROM AuditLog al WHERE " +
          "al.userId = :userId AND " +
          "al.eventType = :eventType AND " +
          "al.timestamp BETWEEN :start AND :end")
  List<AuditLog> findAuditLogs(
          @Param("userId") String userId,
          @Param("eventType") EventType eventType,
          @Param("start") LocalDateTime start,
          @Param("end") LocalDateTime end
  );

  // Failed login attempts
  @Query("SELECT al FROM AuditLog al WHERE " +
          "al.username = :username AND " +
          "al.eventType = 'LOGIN_FAILED' AND " +
          "al.timestamp >= :since " +
          "ORDER BY al.timestamp DESC")
  List<AuditLog> findFailedLoginAttempts(
          @Param("username") String username,
          @Param("since") LocalDateTime since
  );

  @Query("SELECT COUNT(al) FROM AuditLog al WHERE " +
          "al.username = :username AND " +
          "al.eventType = 'LOGIN_FAILED' AND " +
          "al.timestamp >= :since")
  long countFailedLoginAttempts(
          @Param("username") String username,
          @Param("since") LocalDateTime since
  );

  // Statistics
  @Query("SELECT al.eventType, COUNT(al) FROM AuditLog al " +
          "WHERE al.timestamp BETWEEN :start AND :end " +
          "GROUP BY al.eventType")
  List<Object[]> countEventTypesBetween(
          @Param("start") LocalDateTime start,
          @Param("end") LocalDateTime end
  );

  @Query("SELECT al.success, COUNT(al) FROM AuditLog al " +
          "WHERE al.eventType = :eventType AND al.timestamp >= :since " +
          "GROUP BY al.success")
  List<Object[]> countSuccessFailureByEventType(
          @Param("eventType") EventType eventType,
          @Param("since") LocalDateTime since
  );

  // Recent activity
  @Query("SELECT al FROM AuditLog al WHERE al.userId = :userId ORDER BY al.timestamp DESC")
  Page<AuditLog> findRecentActivityByUserId(@Param("userId") String userId, Pageable pageable);

  // Suspicious activity
  @Query("SELECT al FROM AuditLog al WHERE " +
          "al.userId = :userId AND " +
          "al.success = false AND " +
          "al.timestamp >= :since " +
          "GROUP BY al.ipAddress " +
          "HAVING COUNT(al) >= :threshold")
  List<AuditLog> findSuspiciousActivity(
          @Param("userId") String userId,
          @Param("since") LocalDateTime since,
          @Param("threshold") long threshold
  );

  // Cleanup old logs
  @Query("DELETE FROM AuditLog al WHERE al.timestamp < :cutoffDate")
  void deleteOldLogs(@Param("cutoffDate") LocalDateTime cutoffDate);
}
