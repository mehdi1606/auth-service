package com.stock.authservice.dto.request;

import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PermissionAssignRequest {

    @NotEmpty(message = "At least one permission ID is required")
    private Set<String> permissionIds;
}
