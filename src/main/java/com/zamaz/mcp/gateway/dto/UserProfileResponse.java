package com.zamaz.mcp.gateway.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * Response DTO for user profile information
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserProfileResponse {

    private String userId;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private boolean emailVerified;
    private boolean enabled;
    private LocalDateTime createdAt;
    private LocalDateTime lastLoginAt;
    private LocalDateTime passwordChangedAt;
    private String currentOrganizationId;
    private List<Map<String, Object>> organizations;
    private List<String> roles;
    private String message; // For informational messages
}