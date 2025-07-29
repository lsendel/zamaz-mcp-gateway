package com.zamaz.mcp.gateway.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Response DTO for account deactivation
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccountDeactivationResponse {

    private String message;
    private LocalDateTime deactivatedAt;
}