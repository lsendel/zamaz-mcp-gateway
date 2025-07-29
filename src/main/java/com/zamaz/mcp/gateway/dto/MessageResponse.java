package com.zamaz.mcp.gateway.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Generic message response DTO.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class MessageResponse {
    private String message;
    private boolean success = true;
    
    public MessageResponse(String message) {
        this.message = message;
    }
}