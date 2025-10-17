package com.stock.authservice.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PermissionResponse {

    private String id;
    private String resource;
    private String action;
    private String scope;
    private String description;
    private String permissionString; // resource:action:scope
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
