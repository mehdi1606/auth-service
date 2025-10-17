package com.stock.authservice.dto.response;

import com.stock.authservice.entity.AuditLog.EventType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditLogResponse {

    private String id;
    private String userId;
    private String username;
    private EventType eventType;
    private String ipAddress;
    private String userAgent;
    private Boolean success;
    private String reason;
    private String metadata;
    private LocalDateTime timestamp;
}
