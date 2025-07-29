package com.zamaz.mcp.gateway.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response DTO for email verification
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailVerificationResponse {

    private String email;
    private boolean verified;
    private String message;
}