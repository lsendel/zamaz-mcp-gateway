package com.zamaz.mcp.gateway.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Token validation response DTO.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenValidationResponse {
    
    private boolean valid;
    private String userId;
    private String username;
    private String organizationId;
    private Long expiresIn; // seconds remaining
    private String error; // Only populated if invalid
}