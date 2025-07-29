package com.zamaz.mcp.gateway.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response DTO for user registration
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRegistrationResponse {

    private String userId;
    private String email;
    private String message;
    private boolean verificationRequired;
    private String verificationToken; // Only for testing environments
}