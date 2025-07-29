package com.zamaz.mcp.gateway.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Switch organization request DTO.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SwitchOrganizationRequest {
    
    @NotBlank(message = "Organization ID is required")
    private String organizationId;
}