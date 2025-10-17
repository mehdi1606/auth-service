package com.stock.authservice.repository;

import com.stock.authservice.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, String> {

    // Basic queries
    Optional<Role> findByName(String name);

    boolean existsByName(String name);

    // Active roles
    List<Role> findByIsActive(Boolean isActive);

    Optional<Role> findByNameAndIsActive(String name, Boolean isActive);

    // System roles
    List<Role> findByIsSystem(Boolean isSystem);

    List<Role> findByIsSystemAndIsActive(Boolean isSystem, Boolean isActive);

    // Search
    @Query("SELECT r FROM Role r WHERE " +
            "LOWER(r.name) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
            "LOWER(r.description) LIKE LOWER(CONCAT('%', :search, '%'))")
    List<Role> searchRoles(@Param("search") String search);

    // Permission-based queries
    @Query("SELECT r FROM Role r JOIN r.permissions p WHERE p.id = :permissionId")
    List<Role> findByPermissionId(@Param("permissionId") String permissionId);

    @Query("SELECT r FROM Role r JOIN r.permissions p WHERE p.resource = :resource AND p.action = :action")
    List<Role> findByPermission(
            @Param("resource") String resource,
            @Param("action") String action
    );

    // User count per role
    @Query("SELECT r, COUNT(u) FROM Role r LEFT JOIN r.users u GROUP BY r")
    List<Object[]> countUsersPerRole();

    @Query("SELECT COUNT(u) FROM User u JOIN u.roles r WHERE r.id = :roleId")
    long countUsersByRoleId(@Param("roleId") String roleId);

    // Get roles with specific permission count
    @Query("SELECT r FROM Role r WHERE SIZE(r.permissions) >= :minPermissions")
    List<Role> findRolesWithMinPermissions(@Param("minPermissions") int minPermissions);
}
