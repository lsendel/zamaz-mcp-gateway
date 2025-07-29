package com.zamaz.mcp.gateway.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response DTO for password reset operations
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PasswordResetResponse {

    private String message;
    private String resetToken; // Only for testing environments
}