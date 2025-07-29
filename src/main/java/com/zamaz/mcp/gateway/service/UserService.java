package com.zamaz.mcp.gateway.service;

import com.zamaz.mcp.security.model.McpUser;

/**
 * Service interface for user management operations.
 */
public interface UserService {
    
    /**
     * Save or update a user.
     */
    void save(McpUser user);
    
    /**
     * Find user by ID.
     */
    McpUser findById(String userId);
    
    /**
     * Delete a user.
     */
    void delete(String userId);
    
    /**
     * Check if user exists.
     */
    boolean exists(String userId);
}