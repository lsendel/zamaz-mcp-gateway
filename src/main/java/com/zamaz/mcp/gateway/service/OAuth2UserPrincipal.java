package com.zamaz.mcp.gateway.service;

import com.zamaz.mcp.security.model.McpUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;

/**
 * OAuth2 user principal that wraps McpUser and provides OAuth2User interface.
 */
public class OAuth2UserPrincipal implements OAuth2User {

    private final McpUser user;
    private final Map<String, Object> attributes;

    public OAuth2UserPrincipal(McpUser user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getAuthorities();
    }

    @Override
    public String getName() {
        return user.getUsername();
    }

    /**
     * Get the underlying McpUser.
     */
    public McpUser getUser() {
        return user;
    }

    /**
     * Get user ID.
     */
    public String getUserId() {
        return user.getId();
    }

    /**
     * Get user email.
     */
    public String getEmail() {
        return user.getEmail();
    }

    /**
     * Get user first name.
     */
    public String getFirstName() {
        return user.getFirstName();
    }

    /**
     * Get user last name.
     */
    public String getLastName() {
        return user.getLastName();
    }

    /**
     * Check if email is verified.
     */
    public boolean isEmailVerified() {
        return user.isEmailVerified();
    }
}