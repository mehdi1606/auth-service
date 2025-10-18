package com.stock.authservice.controller;

import com.stock.authservice.dto.request.PermissionAssignRequest;
import com.stock.authservice.dto.request.RoleCreateRequest;
import com.stock.authservice.dto.response.ApiResponse;
import com.stock.authservice.dto.response.PageResponse;
import com.stock.authservice.dto.response.RoleResponse;
import com.stock.authservice.service.RoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/roles")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Role Management", description = "Role CRUD and permission assignment")
@SecurityRequirement(name = "Bearer Authentication")
@PreAuthorize("hasRole('ADMIN')")
public class RoleController {

    private final RoleService roleService;

    // ==================== CREATE ROLE ====================

    @PostMapping
    @Operation(summary = "Create role", description = "Create a new role (Admin only)")
    public ResponseEntity<ApiResponse<RoleResponse>> createRole(@Valid @RequestBody RoleCreateRequest request) {
        log.info("POST /api/roles - Create role: {}", request.getName());

        ApiResponse<RoleResponse> response = roleService.createRole(request);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // ==================== GET ROLE ====================

    @GetMapping("/{id}")
    @Operation(summary = "Get role by ID", description = "Get role details by ID")
    public ResponseEntity<RoleResponse> getRoleById(@PathVariable String id) {
        log.info("GET /api/roles/{} - Get role by ID", id);

        RoleResponse response = roleService.getRoleById(id);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/name/{name}")
    @Operation(summary = "Get role by name", description = "Get role details by name")
    public ResponseEntity<RoleResponse> getRoleByName(@PathVariable String name) {
        log.info("GET /api/roles/name/{} - Get role by name", name);

        RoleResponse response = roleService.getRoleByName(name);

        return ResponseEntity.ok(response);
    }

    // ==================== GET ALL ROLES ====================

    @GetMapping
    @Operation(summary = "Get all roles", description = "Get paginated list of all roles")
    public ResponseEntity<PageResponse<RoleResponse>> getAllRoles(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "name") String sortBy,
            @RequestParam(defaultValue = "ASC") String sortDirection) {
        log.info("GET /api/roles - Get all roles (page: {}, size: {})", page, size);

        PageResponse<RoleResponse> response = roleService.getAllRoles(page, size, sortBy, sortDirection);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/active")
    @Operation(summary = "Get active roles", description = "Get list of active roles")
    public ResponseEntity<List<RoleResponse>> getActiveRoles() {
        log.info("GET /api/roles/active - Get active roles");

        List<RoleResponse> response = roleService.getActiveRoles();

        return ResponseEntity.ok(response);
    }

    // ==================== UPDATE ROLE ====================

    @PutMapping("/{id}")
    @Operation(summary = "Update role", description = "Update role details (Admin only)")
    public ResponseEntity<ApiResponse<RoleResponse>> updateRole(
            @PathVariable String id,
            @Valid @RequestBody RoleCreateRequest request) {
        log.info("PUT /api/roles/{} - Update role", id);

        ApiResponse<RoleResponse> response = roleService.updateRole(id, request);

        return ResponseEntity.ok(response);
    }

    // ==================== DELETE ROLE ====================

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete role", description = "Delete role (Admin only)")
    public ResponseEntity<ApiResponse<Void>> deleteRole(@PathVariable String id) {
        log.info("DELETE /api/roles/{} - Delete role", id);

        ApiResponse<Void> response = roleService.deleteRole(id);

        return ResponseEntity.ok(response);
    }

    // ==================== PERMISSION ASSIGNMENT ====================

    @PostMapping("/{roleId}/permissions")
    @Operation(summary = "Assign permissions", description = "Assign permissions to role (Admin only)")
    public ResponseEntity<ApiResponse<Void>> assignPermissions(
            @PathVariable String roleId,
            @Valid @RequestBody PermissionAssignRequest request) {
        log.info("POST /api/roles/{}/permissions - Assign permissions to role", roleId);

        ApiResponse<Void> response = roleService.assignPermissions(roleId, request);

        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{roleId}/permissions")
    @Operation(summary = "Revoke permissions", description = "Revoke permissions from role (Admin only)")
    public ResponseEntity<ApiResponse<Void>> revokePermissions(
            @PathVariable String roleId,
            @Valid @RequestBody PermissionAssignRequest request) {
        log.info("DELETE /api/roles/{}/permissions - Revoke permissions from role", roleId);

        ApiResponse<Void> response = roleService.revokePermissions(roleId, request);

        return ResponseEntity.ok(response);
    }
}
