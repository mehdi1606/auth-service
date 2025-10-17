package com.stock.authservice.repository;

import com.stock.authservice.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, String> {

    // Basic queries
    Optional<Permission> findByResourceAndAction(String resource, String action);

    Optional<Permission> findByResourceAndActionAndScope(String resource, String action, String scope);

    boolean existsByResourceAndAction(String resource, String action);

    // Resource-based queries
    List<Permission> findByResource(String resource);

    List<Permission> findByAction(String action);

    List<Permission> findByScope(String scope);

    // Multiple resources
    List<Permission> findByResourceIn(List<String> resources);

    // Search queries
    @Query("SELECT p FROM Permission p WHERE " +
            "LOWER(p.resource) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
            "LOWER(p.action) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
            "LOWER(p.description) LIKE LOWER(CONCAT('%', :search, '%'))")
    List<Permission> searchPermissions(@Param("search") String search);

    // Role-based queries
    @Query("SELECT p FROM Permission p JOIN p.roles r WHERE r.id = :roleId")
    List<Permission> findByRoleId(@Param("roleId") String roleId);

    @Query("SELECT p FROM Permission p JOIN p.roles r WHERE r.name = :roleName")
    List<Permission> findByRoleName(@Param("roleName") String roleName);

    // Get permissions for a user (through roles)
    @Query("SELECT DISTINCT p FROM Permission p " +
            "JOIN p.roles r " +
            "JOIN r.users u " +
            "WHERE u.id = :userId")
    List<Permission> findByUserId(@Param("userId") String userId);

    @Query("SELECT DISTINCT p FROM Permission p " +
            "JOIN p.roles r " +
            "JOIN r.users u " +
            "WHERE u.username = :username")
    List<Permission> findByUsername(@Param("username") String username);

    // Check if user has specific permission
    @Query("SELECT CASE WHEN COUNT(p) > 0 THEN true ELSE false END " +
            "FROM Permission p " +
            "JOIN p.roles r " +
            "JOIN r.users u " +
            "WHERE u.id = :userId " +
            "AND p.resource = :resource " +
            "AND p.action = :action")
    boolean userHasPermission(
            @Param("userId") String userId,
            @Param("resource") String resource,
            @Param("action") String action
    );

    // Statistics
    @Query("SELECT COUNT(DISTINCT r) FROM Permission p JOIN p.roles r WHERE p.id = :permissionId")
    long countRolesByPermissionId(@Param("permissionId") String permissionId);

    // Get all unique resources
    @Query("SELECT DISTINCT p.resource FROM Permission p ORDER BY p.resource")
    List<String> findAllResources();

    // Get all unique actions
    @Query("SELECT DISTINCT p.action FROM Permission p ORDER BY p.action")
    List<String> findAllActions();
}
