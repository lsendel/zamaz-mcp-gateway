package com.zamaz.mcp.gateway.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response DTO for password change operation
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PasswordChangeResponse {

    private String message;
}