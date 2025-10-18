package com.stock.authservice.controller;

import com.stock.authservice.constants.ApiConstants;
import com.stock.authservice.dto.request.UserCreateRequest;
import com.stock.authservice.dto.request.UserUpdateRequest;
import com.stock.authservice.dto.response.ApiResponse;
import com.stock.authservice.dto.response.PageResponse;
import com.stock.authservice.dto.response.UserResponse;
import com.stock.authservice.service.UserService;
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

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "User Management", description = "User CRUD operations")
@SecurityRequirement(name = "Bearer Authentication")
public class UserController {

    private final UserService userService;

    // ==================== CREATE USER ====================

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Create user", description = "Create a new user (Admin only)")
    public ResponseEntity<ApiResponse<UserResponse>> createUser(@Valid @RequestBody UserCreateRequest request) {
        log.info("POST /api/users - Create user: {}", request.getUsername());

        ApiResponse<UserResponse> response = userService.createUser(request);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // ==================== GET USER ====================

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER') or #id == authentication.principal.id")
    @Operation(summary = "Get user by ID", description = "Get user details by ID")
    public ResponseEntity<UserResponse> getUserById(@PathVariable String id) {
        log.info("GET /api/users/{} - Get user by ID", id);

        UserResponse response = userService.getUserById(id);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/username/{username}")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @Operation(summary = "Get user by username", description = "Get user details by username")
    public ResponseEntity<UserResponse> getUserByUsername(@PathVariable String username) {
        log.info("GET /api/users/username/{} - Get user by username", username);

        UserResponse response = userService.getUserByUsername(username);

        return ResponseEntity.ok(response);
    }

    // ==================== GET CURRENT USER ====================

    @GetMapping("/me")
    @Operation(summary = "Get current user", description = "Get authenticated user details")
    public ResponseEntity<UserResponse> getCurrentUser() {
        log.info("GET /api/users/me - Get current user");

        String username = org.springframework.security.core.context.SecurityContextHolder
                .getContext().getAuthentication().getName();

        UserResponse response = userService.getUserByUsername(username);

        return ResponseEntity.ok(response);
    }

    // ==================== GET ALL USERS ====================

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @Operation(summary = "Get all users", description = "Get paginated list of all users")
    public ResponseEntity<PageResponse<UserResponse>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "DESC") String sortDirection) {
        log.info("GET /api/users - Get all users (page: {}, size: {})", page, size);

        PageResponse<UserResponse> response = userService.getAllUsers(page, size, sortBy, sortDirection);

        return ResponseEntity.ok(response);
    }

    // ==================== SEARCH USERS ====================

    @GetMapping("/search")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @Operation(summary = "Search users", description = "Search users by username or email")
    public ResponseEntity<PageResponse<UserResponse>> searchUsers(
            @RequestParam String query,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        log.info("GET /api/users/search?query={} - Search users", query);

        PageResponse<UserResponse> response = userService.searchUsers(query, page, size);

        return ResponseEntity.ok(response);
    }

    // ==================== UPDATE USER ====================

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")
    @Operation(summary = "Update user", description = "Update user details")
    public ResponseEntity<ApiResponse<UserResponse>> updateUser(
            @PathVariable String id,
            @Valid @RequestBody UserUpdateRequest request) {
        log.info("PUT /api/users/{} - Update user", id);

        ApiResponse<UserResponse> response = userService.updateUser(id, request);

        return ResponseEntity.ok(response);
    }

    // ==================== DELETE USER ====================

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Delete user", description = "Delete user (Admin only)")
    public ResponseEntity<ApiResponse<Void>> deleteUser(@PathVariable String id) {
        log.info("DELETE /api/users/{} - Delete user", id);

        ApiResponse<Void> response = userService.deleteUser(id);

        return ResponseEntity.ok(response);
    }

    // ==================== ACTIVATE / DEACTIVATE USER ====================

    @PostMapping("/{id}/activate")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Activate user", description = "Activate user account (Admin only)")
    public ResponseEntity<ApiResponse<Void>> activateUser(@PathVariable String id) {
        log.info("POST /api/users/{}/activate - Activate user", id);

        ApiResponse<Void> response = userService.activateUser(id);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/{id}/deactivate")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Deactivate user", description = "Deactivate user account (Admin only)")
    public ResponseEntity<ApiResponse<Void>> deactivateUser(@PathVariable String id) {
        log.info("POST /api/users/{}/deactivate - Deactivate user", id);

        ApiResponse<Void> response = userService.deactivateUser(id);

        return ResponseEntity.ok(response);
    }

    // ==================== ROLE ASSIGNMENT ====================

    @PostMapping("/{userId}/roles/{roleId}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Assign role to user", description = "Assign a role to user (Admin only)")
    public ResponseEntity<ApiResponse<Void>> assignRole(
            @PathVariable String userId,
            @PathVariable String roleId) {
        log.info("POST /api/users/{}/roles/{} - Assign role to user", userId, roleId);

        ApiResponse<Void> response = userService.assignRoleToUser(userId, roleId);

        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{userId}/roles/{roleId}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Remove role from user", description = "Remove a role from user (Admin only)")
    public ResponseEntity<ApiResponse<Void>> removeRole(
            @PathVariable String userId,
            @PathVariable String roleId) {
        log.info("DELETE /api/users/{}/roles/{} - Remove role from user", userId, roleId);

        ApiResponse<Void> response = userService.removeRoleFromUser(userId, roleId);

        return ResponseEntity.ok(response);
    }
}
