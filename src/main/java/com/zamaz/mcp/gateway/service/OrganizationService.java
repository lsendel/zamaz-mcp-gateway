package com.zamaz.mcp.gateway.service;

import java.util.Date;

/**
 * Service interface for organization management operations.
 */
public interface OrganizationService {
    
    /**
     * Create a new organization.
     */
    String create(String name, String ownerId);
    
    /**
     * Check if organization exists.
     */
    boolean exists(String organizationId);
    
    /**
     * Get organization name.
     */
    String getName(String organizationId);
    
    /**
     * Add member to organization.
     */
    void addMember(String organizationId, String userId, String role);
    
    /**
     * Remove member from organization.
     */
    void removeMember(String organizationId, String userId);
    
    /**
     * Get user's role in organization.
     */
    String getUserRole(String organizationId, String userId);
    
    /**
     * Get member join date.
     */
    Date getMemberJoinDate(String organizationId, String userId);
    
    /**
     * Update organization details.
     */
    void update(String organizationId, String name);
    
    /**
     * Delete organization.
     */
    void delete(String organizationId);
}