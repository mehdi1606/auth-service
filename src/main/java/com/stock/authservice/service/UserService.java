package com.stock.authservice.service;

import com.stock.authservice.constants.RoleConstants;
import com.stock.authservice.dto.request.UserCreateRequest;
import com.stock.authservice.dto.request.UserUpdateRequest;
import com.stock.authservice.dto.response.ApiResponse;
import com.stock.authservice.dto.response.PageResponse;
import com.stock.authservice.dto.response.RoleResponse;
import com.stock.authservice.dto.response.UserResponse;
import com.stock.authservice.entity.Role;
import com.stock.authservice.entity.User;
import com.stock.authservice.event.UserEventPublisher;
import com.stock.authservice.event.dto.UserCreatedEvent;
import com.stock.authservice.event.dto.UserDeletedEvent;
import com.stock.authservice.event.dto.UserUpdatedEvent;
import com.stock.authservice.exception.DuplicateResourceException;
import com.stock.authservice.exception.ResourceNotFoundException;
import com.stock.authservice.repository.RoleRepository;
import com.stock.authservice.repository.UserRepository;
import com.stock.authservice.security.SecurityContextHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecurityContextHelper securityContextHelper;
    private final UserEventPublisher userEventPublisher;

    // ==================== CRUD OPERATIONS ====================

    @Transactional
    public ApiResponse<UserResponse> createUser(UserCreateRequest request) {
        log.info("Creating user: {}", request.getUsername());

        // Check if username exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new DuplicateResourceException("User", "username", request.getUsername());
        }

        // Check if email exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateResourceException("User", "email", request.getEmail());
        }

        // Create user
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .phoneNumber(request.getPhoneNumber())
                .isActive(request.getIsActive() != null ? request.getIsActive() : true)
                .isEmailVerified(false)
                .isPhoneVerified(false)
                .mfaEnabled(false)
                .failedLoginAttempts(0)
                .build();

        // Assign roles
        if (request.getRoleIds() != null && !request.getRoleIds().isEmpty()) {
            Set<Role> roles = roleRepository.findAllById(request.getRoleIds())
                    .stream()
                    .collect(Collectors.toSet());
            user.setRoles(roles);
        } else {
            assignDefaultRole(user);
        }

        user = userRepository.save(user);

        // Publish event
        userEventPublisher.publishUserCreated(UserCreatedEvent.builder()
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .roles(user.getRoles().stream().map(Role::getName).collect(Collectors.toSet()))
                .createdBy(securityContextHelper.getCurrentUsername())
                .createdAt(LocalDateTime.now())
                .build());

        log.info("User created successfully: {}", user.getUsername());

        return ApiResponse.success("User created successfully", mapToUserResponse(user));
    }

    @Transactional(readOnly = true)
    public UserResponse getUserById(String id) {
        log.debug("Getting user by id: {}", id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", id));

        return mapToUserResponse(user);
    }

    @Transactional(readOnly = true)
    public UserResponse getUserByUsername(String username) {
        log.debug("Getting user by username: {}", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User", "username", username));

        return mapToUserResponse(user);
    }

    @Transactional(readOnly = true)
    public PageResponse<UserResponse> getAllUsers(int page, int size, String sortBy, String sortDirection) {
        log.debug("Getting all users - page: {}, size: {}", page, size);

        Sort.Direction direction = sortDirection.equalsIgnoreCase("ASC") ? Sort.Direction.ASC : Sort.Direction.DESC;
        Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortBy));

        Page<User> userPage = userRepository.findAll(pageable);

        return PageResponse.<UserResponse>builder()
                .content(userPage.getContent().stream()
                        .map(this::mapToUserResponse)
                        .collect(Collectors.toList()))
                .pageNumber(userPage.getNumber())
                .pageSize(userPage.getSize())
                .totalElements(userPage.getTotalElements())
                .totalPages(userPage.getTotalPages())
                .last(userPage.isLast())
                .first(userPage.isFirst())
                .build();
    }

    @Transactional(readOnly = true)
    public PageResponse<UserResponse> searchUsers(String query, int page, int size) {
        log.debug("Searching users with query: {}", query);

        Pageable pageable = PageRequest.of(page, size);
        Page<User> userPage = userRepository.searchUsers(query, pageable);

        return PageResponse.<UserResponse>builder()
                .content(userPage.getContent().stream()
                        .map(this::mapToUserResponse)
                        .collect(Collectors.toList()))
                .pageNumber(userPage.getNumber())
                .pageSize(userPage.getSize())
                .totalElements(userPage.getTotalElements())
                .totalPages(userPage.getTotalPages())
                .last(userPage.isLast())
                .first(userPage.isFirst())
                .build();
    }

    @Transactional
    public ApiResponse<UserResponse> updateUser(String id, UserUpdateRequest request) {
        log.info("Updating user: {}", id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", id));

        Map<String, Object> changedFields = new HashMap<>();

        // Update email
        if (request.getEmail() != null && !request.getEmail().equals(user.getEmail())) {
            if (userRepository.existsByEmail(request.getEmail())) {
                throw new DuplicateResourceException("User", "email", request.getEmail());
            }
            changedFields.put("email", request.getEmail());
            user.setEmail(request.getEmail());
            user.setIsEmailVerified(false); // Need to re-verify
        }

        // Update other fields
        if (request.getFirstName() != null) {
            changedFields.put("firstName", request.getFirstName());
            user.setFirstName(request.getFirstName());
        }

        if (request.getLastName() != null) {
            changedFields.put("lastName", request.getLastName());
            user.setLastName(request.getLastName());
        }

        if (request.getPhoneNumber() != null) {
            changedFields.put("phoneNumber", request.getPhoneNumber());
            user.setPhoneNumber(request.getPhoneNumber());
        }

        if (request.getIsActive() != null) {
            changedFields.put("isActive", request.getIsActive());
            user.setIsActive(request.getIsActive());
        }
// Update roles
        if (request.getRoleIds() != null) {
            Set<Role> roles = roleRepository.findAllById(request.getRoleIds())
                    .stream()
                    .collect(Collectors.toSet());
            changedFields.put("roles", request.getRoleIds());
            user.setRoles(roles);
        }

        // Update preferences
        if (request.getPreferences() != null) {
            changedFields.put("preferences", request.getPreferences());
            user.setPreferences(request.getPreferences());
        }

        user = userRepository.save(user);

        // Publish event
        userEventPublisher.publishUserUpdated(UserUpdatedEvent.builder()
                .userId(user.getId())
                .username(user.getUsername())
                .changedFields(changedFields)
                .updatedBy(securityContextHelper.getCurrentUsername())
                .updatedAt(LocalDateTime.now())
                .build());

        log.info("User updated successfully: {}", user.getUsername());

        return ApiResponse.success("User updated successfully", mapToUserResponse(user));
    }

    @Transactional
    public ApiResponse<Void> deleteUser(String id) {
        log.info("Deleting user: {}", id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", id));

        String username = user.getUsername();
        String email = user.getEmail();

        userRepository.delete(user);

        // Publish event
        userEventPublisher.publishUserDeleted(UserDeletedEvent.builder()
                .userId(id)
                .username(username)
                .email(email)
                .deletedBy(securityContextHelper.getCurrentUsername())
                .deletedAt(LocalDateTime.now())
                .deletionReason("Manual deletion")
                .build());

        log.info("User deleted successfully: {}", username);

        return ApiResponse.success("User deleted successfully", null);
    }

    // ==================== ACTIVATION / DEACTIVATION ====================

    @Transactional
    public ApiResponse<Void> activateUser(String id) {
        log.info("Activating user: {}", id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", id));

        user.setIsActive(true);
        user.setLockedUntil(null);
        user.setFailedLoginAttempts(0);
        userRepository.save(user);

        // Publish event
        userEventPublisher.publishUserActivated(user.getId(), user.getUsername());

        log.info("User activated successfully: {}", user.getUsername());

        return ApiResponse.success("User activated successfully", null);
    }

    @Transactional
    public ApiResponse<Void> deactivateUser(String id) {
        log.info("Deactivating user: {}", id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", id));

        user.setIsActive(false);
        userRepository.save(user);

        // Publish event
        userEventPublisher.publishUserDeactivated(user.getId(), user.getUsername());

        log.info("User deactivated successfully: {}", user.getUsername());

        return ApiResponse.success("User deactivated successfully", null);
    }

    // ==================== ROLE ASSIGNMENT ====================

    @Transactional
    public ApiResponse<Void> assignRoleToUser(String userId, String roleId) {
        log.info("Assigning role {} to user {}", roleId, userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "id", roleId));

        user.getRoles().add(role);
        userRepository.save(user);

        log.info("Role assigned successfully");

        return ApiResponse.success("Role assigned successfully", null);
    }

    @Transactional
    public ApiResponse<Void> removeRoleFromUser(String userId, String roleId) {
        log.info("Removing role {} from user {}", roleId, userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "id", roleId));

        user.getRoles().remove(role);
        userRepository.save(user);

        log.info("Role removed successfully");

        return ApiResponse.success("Role removed successfully", null);
    }

    // ==================== HELPER METHODS ====================

    public void assignDefaultRole(User user) {
        Role defaultRole = roleRepository.findByName(RoleConstants.USER)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "name", RoleConstants.USER));

        user.getRoles().add(defaultRole);
    }

    public UserResponse mapToUserResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .phoneNumber(user.getPhoneNumber())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .isActive(user.getIsActive())
                .isEmailVerified(user.getIsEmailVerified())
                .isPhoneVerified(user.getIsPhoneVerified())
                .mfaEnabled(user.getMfaEnabled())
                .lastLogin(user.getLastLogin())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .roles(user.getRoles().stream()
                        .map(this::mapToRoleResponse)
                        .collect(Collectors.toSet()))
                .build();
    }

    private RoleResponse mapToRoleResponse(Role role) {
        return RoleResponse.builder()
                .id(role.getId())
                .name(role.getName())
                .description(role.getDescription())
                .isSystem(role.getIsSystem())
                .isActive(role.getIsActive())
                .createdAt(role.getCreatedAt())
                .updatedAt(role.getUpdatedAt())
                .build();
    }
}
