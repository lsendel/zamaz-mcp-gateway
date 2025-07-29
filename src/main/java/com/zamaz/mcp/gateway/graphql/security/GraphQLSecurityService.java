package com.zamaz.mcp.gateway.graphql.security;

import com.zamaz.mcp.security.jwt.JwtService;
import graphql.schema.DataFetchingEnvironment;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * Security service for GraphQL operations
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class GraphQLSecurityService {
    
    private final JwtService jwtService;

    /**
     * Check if user is authenticated
     */
    public boolean isAuthenticated(DataFetchingEnvironment environment) {
        Object context = environment.getContext();
        
        if (context instanceof graphql.kickstart.servlet.context.GraphQLServletContext) {
            graphql.kickstart.servlet.context.GraphQLServletContext servletContext = 
                (graphql.kickstart.servlet.context.GraphQLServletContext) context;
            
            HttpServletRequest httpRequest = servletContext.getHttpServletRequest();
            String authHeader = httpRequest.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                return validateToken(token);
            }
        }
        
        return false;
    }

    /**
     * Check if user has required role
     */
    public boolean hasRole(DataFetchingEnvironment environment, String requiredRole) {
        String userRole = getUserRole(environment);
        return hasRoleHierarchy(userRole, requiredRole);
    }

    /**
     * Get user role from context
     */
    public String getUserRole(DataFetchingEnvironment environment) {
        Object context = environment.getContext();
        
        if (context instanceof graphql.kickstart.servlet.context.GraphQLServletContext) {
            graphql.kickstart.servlet.context.GraphQLServletContext servletContext = 
                (graphql.kickstart.servlet.context.GraphQLServletContext) context;
            
            HttpServletRequest httpRequest = servletContext.getHttpServletRequest();
            String authHeader = httpRequest.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                return extractRoleFromToken(token);
            }
        }
        
        return "ANONYMOUS";
    }

    /**
     * Check if user has specific permission
     */
    public boolean hasPermission(DataFetchingEnvironment environment, String permission) {
        String userRole = getUserRole(environment);
        return hasPermissionForRole(userRole, permission);
    }

    /**
     * Get user ID from context
     */
    public String getUserId(DataFetchingEnvironment environment) {
        Object context = environment.getContext();
        
        if (context instanceof graphql.kickstart.servlet.context.GraphQLServletContext) {
            graphql.kickstart.servlet.context.GraphQLServletContext servletContext = 
                (graphql.kickstart.servlet.context.GraphQLServletContext) context;
            
            HttpServletRequest httpRequest = servletContext.getHttpServletRequest();
            String authHeader = httpRequest.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                return extractUserIdFromToken(token);
            }
        }
        
        return null;
    }

    /**
     * Get organization ID from context
     */
    public String getOrganizationId(DataFetchingEnvironment environment) {
        Object context = environment.getContext();
        
        if (context instanceof graphql.kickstart.servlet.context.GraphQLServletContext) {
            graphql.kickstart.servlet.context.GraphQLServletContext servletContext = 
                (graphql.kickstart.servlet.context.GraphQLServletContext) context;
            
            // Try X-Organization-ID header first
            String orgHeader = servletContext.getHttpServletRequest().getHeader("X-Organization-ID");
            if (orgHeader != null) {
                return orgHeader;
            }
            
            // Fall back to token
            String authHeader = servletContext.getHttpServletRequest().getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                return extractOrganizationIdFromToken(token);
            }
        }
        
        return null;
    }

    private boolean validateToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }
        
        try {
            return jwtService.isTokenValid(token);
        } catch (Exception e) {
            log.warn("JWT validation failed", e);
            return false;
        }
    }

    private String extractRoleFromToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            return "ANONYMOUS";
        }
        
        try {
            List<String> roles = jwtService.extractRoles(token);
            if (roles == null || roles.isEmpty()) {
                return "USER"; // Default role for authenticated users
            }
            
            // Return the highest priority role
            if (roles.contains("SUPER_ADMIN")) return "SUPER_ADMIN";
            if (roles.contains("ADMIN")) return "ADMIN";
            if (roles.contains("MODERATOR")) return "MODERATOR";
            return "USER";
        } catch (Exception e) {
            log.warn("Failed to extract role from token", e);
            return "ANONYMOUS";
        }
    }

    private String extractUserIdFromToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            return null;
        }
        
        try {
            return jwtService.extractUserId(token);
        } catch (Exception e) {
            log.warn("Failed to extract user ID from token", e);
            return null;
        }
    }

    private String extractOrganizationIdFromToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            return null;
        }
        
        try {
            return jwtService.extractOrganizationId(token);
        } catch (Exception e) {
            log.warn("Failed to extract organization ID from token", e);
            return null;
        }
    }

    private boolean hasRoleHierarchy(String userRole, String requiredRole) {
        // Define role hierarchy
        if (userRole == null) {
            return false;
        }
        
        switch (requiredRole) {
            case "USER":
                return userRole.equals("USER") || userRole.equals("ADMIN") || 
                       userRole.equals("MODERATOR") || userRole.equals("SUPER_ADMIN");
            case "MODERATOR":
                return userRole.equals("MODERATOR") || userRole.equals("ADMIN") || 
                       userRole.equals("SUPER_ADMIN");
            case "ADMIN":
                return userRole.equals("ADMIN") || userRole.equals("SUPER_ADMIN");
            case "SUPER_ADMIN":
                return userRole.equals("SUPER_ADMIN");
            default:
                return false;
        }
    }

    private boolean hasPermissionForRole(String userRole, String permission) {
        if (userRole == null || userRole.equals("ANONYMOUS")) {
            return false;
        }
        
        // Define permissions based on roles
        switch (permission) {
            case "READ":
                return hasRoleHierarchy(userRole, "USER");
            case "write":
                return hasRoleHierarchy(userRole, "USER");
            case "moderate":
                return hasRoleHierarchy(userRole, "MODERATOR");
            case "admin":
                return hasRoleHierarchy(userRole, "ADMIN");
            case "super_admin":
                return hasRoleHierarchy(userRole, "SUPER_ADMIN");
            case "create_organization":
                return hasRoleHierarchy(userRole, "ADMIN");
            case "manage_users":
                return hasRoleHierarchy(userRole, "ADMIN");
            case "delete":
                return hasRoleHierarchy(userRole, "MODERATOR");
            default:
                // For unknown permissions, only allow ADMIN and above
                return hasRoleHierarchy(userRole, "ADMIN");
        }
    }
}