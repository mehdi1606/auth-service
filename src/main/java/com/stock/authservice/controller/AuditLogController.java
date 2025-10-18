package com.stock.authservice.controller;

import com.stock.authservice.dto.response.AuditLogResponse;
import com.stock.authservice.dto.response.PageResponse;
import com.stock.authservice.entity.AuditLog;
import com.stock.authservice.service.AuditLogService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/audit")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Audit Logs", description = "Audit log read operations")
@SecurityRequirement(name = "Bearer Authentication")
@PreAuthorize("hasAnyRole('ADMIN', 'AUDITOR')")
public class AuditLogController {

    private final AuditLogService auditLogService;

    // ==================== GET ALL AUDIT LOGS ====================

    @GetMapping
    @Operation(summary = "Get all audit logs", description = "Get paginated list of all audit logs")
    public ResponseEntity<PageResponse<AuditLogResponse>> getAllAuditLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "timestamp") String sortBy,
            @RequestParam(defaultValue = "DESC") String sortDirection) {
        log.info("GET /api/audit - Get all audit logs (page: {}, size: {})", page, size);

        PageResponse<AuditLogResponse> response = auditLogService.getAuditLogs(page, size, sortBy, sortDirection);

        return ResponseEntity.ok(response);
    }

    // ==================== GET USER AUDIT LOGS ====================

    @GetMapping("/user/{userId}")
    @Operation(summary = "Get user audit logs", description = "Get audit logs for specific user")
    public ResponseEntity<PageResponse<AuditLogResponse>> getUserAuditLogs(
            @PathVariable String userId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        log.info("GET /api/audit/user/{} - Get audit logs for user (page: {}, size: {})", userId, page, size);

        PageResponse<AuditLogResponse> response = auditLogService.getUserAuditLogs(userId, page, size);

        return ResponseEntity.ok(response);
    }

    // ==================== GET AUDIT LOGS BY EVENT TYPE ====================

    @GetMapping("/event/{eventType}")
    @Operation(summary = "Get audit logs by event type", description = "Get audit logs filtered by event type")
    public ResponseEntity<PageResponse<AuditLogResponse>> getAuditLogsByEventType(
            @PathVariable AuditLog.EventType eventType,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        log.info("GET /api/audit/event/{} - Get audit logs by event type (page: {}, size: {})", eventType, page, size);

        PageResponse<AuditLogResponse> response = auditLogService.getAuditLogsByEventType(eventType, page, size);

        return ResponseEntity.ok(response);
    }

    // ==================== GET AUDIT LOGS BY DATE RANGE ====================

    @GetMapping("/range")
    @Operation(summary = "Get audit logs by date range", description = "Get audit logs within date range")
    public ResponseEntity<PageResponse<AuditLogResponse>> getAuditLogsByDateRange(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDate,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDate,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        log.info("GET /api/audit/range - Get audit logs between {} and {}", startDate, endDate);

        PageResponse<AuditLogResponse> response = auditLogService.getAuditLogsByDateRange(startDate, endDate, page, size);
        return ResponseEntity.ok(response);
    }

    // ==================== GET FAILED AUDIT LOGS ====================

    @GetMapping("/failed")
    @Operation(summary = "Get failed audit logs", description = "Get all failed audit events")
    public ResponseEntity<PageResponse<AuditLogResponse>> getFailedAuditLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        log.info("GET /api/audit/failed - Get failed audit logs (page: {}, size: {})", page, size);

        PageResponse<AuditLogResponse> response = auditLogService.getFailedAuditLogs(page, size);

        return ResponseEntity.ok(response);
    }
}
