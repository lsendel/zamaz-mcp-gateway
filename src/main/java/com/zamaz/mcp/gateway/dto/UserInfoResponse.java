package com.zamaz.mcp.gateway.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * User info response DTO.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserInfoResponse {
    
    private String id;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private boolean enabled;
    private Date createdAt;
    private Date lastLoginAt;
    
    private String currentOrganizationId;
    private List<OrganizationMembership> organizations;
    
    private Set<String> globalRoles;
    private Set<String> globalPermissions;
    private Set<String> currentOrgRoles;
    private Set<String> currentOrgPermissions;
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class OrganizationMembership {
        private String organizationId;
        private String organizationName;
        private Set<String> roles;
        private Date joinedAt;
        private boolean isDefault;
    }
}