package com.stock.authservice.service;

import com.stock.authservice.dto.response.AuditLogResponse;
import com.stock.authservice.dto.response.PageResponse;
import com.stock.authservice.entity.AuditLog;
import com.stock.authservice.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;

    // ==================== LOG METHODS ====================

    @Transactional
    public void logSuccessfulLogin(String userId, String username, String ipAddress) {
        log.debug("Logging successful login for user: {}", username);

        AuditLog auditLog = AuditLog.builder()
                .userId(userId)
                .username(username)
                .eventType(AuditLog.EventType.LOGIN)
                .ipAddress(ipAddress)
                .success(true)
                .timestamp(LocalDateTime.now())
                .build();

        auditLogRepository.save(auditLog);
    }

    @Transactional
    public void logFailedLogin(String username, String ipAddress, String reason) {
        log.debug("Logging failed login for user: {}", username);

        AuditLog auditLog = AuditLog.builder()
                .username(username)
                .eventType(AuditLog.EventType.LOGIN_FAILED)
                .ipAddress(ipAddress)
                .success(false)
                .reason(reason)
                .timestamp(LocalDateTime.now())
                .build();

        auditLogRepository.save(auditLog);
    }

    @Transactional
    public void logLogout(String userId, String username, String ipAddress) {
        log.debug("Logging logout for user: {}", username);

        AuditLog auditLog = AuditLog.builder()
                .userId(userId)
                .username(username)
                .eventType(AuditLog.EventType.LOGOUT)
                .ipAddress(ipAddress)
                .success(true)
                .timestamp(LocalDateTime.now())
                .build();

        auditLogRepository.save(auditLog);
    }

    @Transactional
    public void logPasswordChange(String userId, String username, String ipAddress) {
        log.debug("Logging password change for user: {}", username);

        AuditLog auditLog = AuditLog.builder()
                .userId(userId)
                .username(username)
                .eventType(AuditLog.EventType.PASSWORD_CHANGE)
                .ipAddress(ipAddress)
                .success(true)
                .timestamp(LocalDateTime.now())
                .build();

        auditLogRepository.save(auditLog);
    }

    @Transactional
    public void logMfaEnabled(String userId, String username) {
        log.debug("Logging MFA enabled for user: {}", username);

        AuditLog auditLog = AuditLog.builder()
                .userId(userId)
                .username(username)
                .eventType(AuditLog.EventType.MFA_ENABLED)
                .success(true)
                .timestamp(LocalDateTime.now())
                .build();

        auditLogRepository.save(auditLog);
    }

    @Transactional
    public void logMfaDisabled(String userId, String username) {
        log.debug("Logging MFA disabled for user: {}", username);

        AuditLog auditLog = AuditLog.builder()
                .userId(userId)
                .username(username)
                .eventType(AuditLog.EventType.MFA_DISABLED)
                .success(true)
                .timestamp(LocalDateTime.now())
                .build();

        auditLogRepository.save(auditLog);
    }

    @Transactional
    public void logAccountLocked(String userId, String username, String ipAddress) {
        log.debug("Logging account locked for user: {}", username);

        AuditLog auditLog = AuditLog.builder()
                .userId(userId)
                .username(username)
                .eventType(AuditLog.EventType.ACCOUNT_LOCKED)
                .ipAddress(ipAddress)
                .success(true)
                .timestamp(LocalDateTime.now())
                .build();

        auditLogRepository.save(auditLog);
    }

    // ==================== QUERY METHODS ====================

    @Transactional(readOnly = true)
    public PageResponse<AuditLogResponse> getAuditLogs(int page, int size, String sortBy, String sortDirection) {
        log.debug("Getting audit logs - page: {}, size: {}", page, size);

        Sort.Direction direction = sortDirection.equalsIgnoreCase("ASC") ? Sort.Direction.ASC : Sort.Direction.DESC;
        Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortBy));

        Page<AuditLog> auditLogPage = auditLogRepository.findAll(pageable);

        return mapToPageResponse(auditLogPage);
    }

    @Transactional(readOnly = true)
    public PageResponse<AuditLogResponse> getUserAuditLogs(String userId, int page, int size) {
        log.debug("Getting audit logs for user: {}", userId);

        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "timestamp"));
        Page<AuditLog> auditLogPage = auditLogRepository.findByUserId(userId, pageable);

        return mapToPageResponse(auditLogPage);
    }

    @Transactional(readOnly = true)
    public PageResponse<AuditLogResponse> getAuditLogsByEventType(AuditLog.EventType eventType, int page, int size) {
        log.debug("Getting audit logs by event type: {}", eventType);

        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "timestamp"));
        Page<AuditLog> auditLogPage = auditLogRepository.findByEventType(eventType, pageable);

        return mapToPageResponse(auditLogPage);
    }

    @Transactional(readOnly = true)
    public PageResponse<AuditLogResponse> getAuditLogsByDateRange(
            LocalDateTime startDate, LocalDateTime endDate, int page, int size) {
        log.debug("Getting audit logs between {} and {}", startDate, endDate);

        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "timestamp"));
        Page<AuditLog> auditLogPage = auditLogRepository.findByTimestampBetween(startDate, endDate, pageable);

        return mapToPageResponse(auditLogPage);
    }

    @Transactional(readOnly = true)
    public PageResponse<AuditLogResponse> getFailedAuditLogs(int page, int size) {
        log.debug("Getting failed audit logs");

        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "timestamp"));
        Page<AuditLog> auditLogPage = auditLogRepository.findBySuccess(false, pageable);

        return mapToPageResponse(auditLogPage);
    }

    // ==================== CLEANUP ====================

    @Transactional
    public void cleanupOldAuditLogs(int retentionDays) {
        log.info("Cleaning up audit logs older than {} days", retentionDays);

        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(retentionDays);
        auditLogRepository.deleteOldLogs(cutoffDate);

        log.info("Old audit logs cleanup completed successfully");
    }
    // ==================== MAPPER ====================

    private PageResponse<AuditLogResponse> mapToPageResponse(Page<AuditLog> auditLogPage) {
        return PageResponse.<AuditLogResponse>builder()
                .content(auditLogPage.getContent().stream()
                        .map(this::mapToAuditLogResponse)
                        .collect(Collectors.toList()))
                .pageNumber(auditLogPage.getNumber())
                .pageSize(auditLogPage.getSize())
                .totalElements(auditLogPage.getTotalElements())
                .totalPages(auditLogPage.getTotalPages())
                .last(auditLogPage.isLast())
                .first(auditLogPage.isFirst())
                .build();
    }

    private AuditLogResponse mapToAuditLogResponse(AuditLog auditLog) {
        return AuditLogResponse.builder()
                .id(auditLog.getId())
                .userId(auditLog.getUserId())
                .username(auditLog.getUsername())
                .eventType(auditLog.getEventType())
                .ipAddress(auditLog.getIpAddress())
                .userAgent(auditLog.getUserAgent())
                .success(auditLog.getSuccess())
                .reason(auditLog.getReason())
                .metadata(auditLog.getMetadata())
                .timestamp(auditLog.getTimestamp())
                .build();
    }
}
