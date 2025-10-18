package com.stock.authservice.controller;

import com.stock.authservice.dto.response.PageResponse;
import com.stock.authservice.dto.response.PermissionResponse;
import com.stock.authservice.service.PermissionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/permissions")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Permission Management", description = "Permission read operations")
@SecurityRequirement(name = "Bearer Authentication")
@PreAuthorize("hasRole('ADMIN')")
public class PermissionController {

    private final PermissionService permissionService;

    // ==================== GET PERMISSION ====================

    @GetMapping("/{id}")
    @Operation(summary = "Get permission by ID", description = "Get permission details by ID")
    public ResponseEntity<PermissionResponse> getPermissionById(@PathVariable String id) {
        log.info("GET /api/permissions/{} - Get permission by ID", id);

        PermissionResponse response = permissionService.getPermissionById(id);

        return ResponseEntity.ok(response);
    }

    // ==================== GET ALL PERMISSIONS ====================

    @GetMapping
    @Operation(summary = "Get all permissions", description = "Get paginated list of all permissions")
    public ResponseEntity<PageResponse<PermissionResponse>> getAllPermissions(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "resource") String sortBy,
            @RequestParam(defaultValue = "ASC") String sortDirection) {
        log.info("GET /api/permissions - Get all permissions (page: {}, size: {})", page, size);

        PageResponse<PermissionResponse> response = permissionService.getAllPermissions(page, size, sortBy, sortDirection);

        return ResponseEntity.ok(response);
    }

    // ==================== GET PERMISSIONS BY RESOURCE ====================

    @GetMapping("/resource/{resource}")
    @Operation(summary = "Get permissions by resource", description = "Get permissions for a specific resource")
    public ResponseEntity<List<PermissionResponse>> getPermissionsByResource(@PathVariable String resource) {
        log.info("GET /api/permissions/resource/{} - Get permissions by resource", resource);

        List<PermissionResponse> response = permissionService.getPermissionsByResource(resource);

        return ResponseEntity.ok(response);
    }

    // ==================== SEARCH PERMISSIONS ====================

    @GetMapping("/search")
    @Operation(summary = "Search permissions", description = "Search permissions by query")
    public ResponseEntity<List<PermissionResponse>> searchPermissions(@RequestParam String query) {
        log.info("GET /api/permissions/search?query={} - Search permissions", query);

        List<PermissionResponse> response = permissionService.searchPermissions(query);

        return ResponseEntity.ok(response);
    }
}
