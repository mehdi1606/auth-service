package com.stock.authservice.security;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.stock.authservice.entity.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.stream.Collectors;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CustomUserDetails implements UserDetails {

    private String id;
    private String username;
    private String email;

    @JsonIgnore
    private String password;

    private boolean enabled;
    private boolean accountNonExpired;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;
    private Collection<? extends GrantedAuthority> authorities;

    public static CustomUserDetails build(User user) {
        Collection<GrantedAuthority> authorities = user.getRoles().stream()
                .flatMap(role -> {
                    // Add role
                    var roleAuthority = new SimpleGrantedAuthority("ROLE_" + role.getName());

                    // Add permissions
                    var permissionAuthorities = role.getPermissions().stream()
                            .map(permission -> new SimpleGrantedAuthority(permission.getPermissionString()))
                            .collect(Collectors.toList());

                    permissionAuthorities.add(roleAuthority);
                    return permissionAuthorities.stream();
                })
                .collect(Collectors.toList());

        boolean accountNonLocked = user.getLockedUntil() == null ||
                user.getLockedUntil().isBefore(LocalDateTime.now());

        return new CustomUserDetails(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getPasswordHash(),
                user.getIsActive(),
                true, // accountNonExpired
                accountNonLocked,
                true, // credentialsNonExpired
                authorities
        );
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
