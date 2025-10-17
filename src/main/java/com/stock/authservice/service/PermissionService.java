package com.stock.authservice.service;

import com.stock.authservice.dto.response.PageResponse;
import com.stock.authservice.dto.response.PermissionResponse;
import com.stock.authservice.entity.Permission;
import com.stock.authservice.exception.ResourceNotFoundException;
import com.stock.authservice.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class PermissionService {

    private final PermissionRepository permissionRepository;

    // ==================== READ OPERATIONS ====================

    @Transactional(readOnly = true)
    public PermissionResponse getPermissionById(String id) {
        log.debug("Getting permission by id: {}", id);

        Permission permission = permissionRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Permission", "id", id));

        return mapToPermissionResponse(permission);
    }

    @Transactional(readOnly = true)
    public PageResponse<PermissionResponse> getAllPermissions(int page, int size, String sortBy, String sortDirection) {
        log.debug("Getting all permissions - page: {}, size: {}", page, size);

        Sort.Direction direction = sortDirection.equalsIgnoreCase("ASC") ? Sort.Direction.ASC : Sort.Direction.DESC;
        Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortBy));

        Page<Permission> permissionPage = permissionRepository.findAll(pageable);

        return PageResponse.<PermissionResponse>builder()
                .content(permissionPage.getContent().stream()
                        .map(this::mapToPermissionResponse)
                        .collect(Collectors.toList()))
                .pageNumber(permissionPage.getNumber())
                .pageSize(permissionPage.getSize())
                .totalElements(permissionPage.getTotalElements())
                .totalPages(permissionPage.getTotalPages())
                .last(permissionPage.isLast())
                .first(permissionPage.isFirst())
                .build();
    }

    @Transactional(readOnly = true)
    public List<PermissionResponse> getPermissionsByResource(String resource) {
        log.debug("Getting permissions by resource: {}", resource);

        return permissionRepository.findByResource(resource).stream()
                .map(this::mapToPermissionResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<PermissionResponse> searchPermissions(String query) {
        log.debug("Searching permissions with query: {}", query);

        return permissionRepository.searchPermissions(query).stream()
                .map(this::mapToPermissionResponse)
                .collect(Collectors.toList());
    }

    // ==================== MAPPER ====================

    public PermissionResponse mapToPermissionResponse(Permission permission) {
        return PermissionResponse.builder()
                .id(permission.getId())
                .resource(permission.getResource())
                .action(permission.getAction())
                .scope(permission.getScope())
                .description(permission.getDescription())
                .permissionString(permission.getPermissionString())
                .createdAt(permission.getCreatedAt())
                .updatedAt(permission.getUpdatedAt())
                .build();
    }
}
