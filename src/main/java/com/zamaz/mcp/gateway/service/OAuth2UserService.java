package com.zamaz.mcp.gateway.service;

import com.zamaz.mcp.gateway.exception.OAuth2AuthenticationException;
import com.zamaz.mcp.security.audit.SecurityAuditLogger;
import com.zamaz.mcp.security.model.McpUser;
import com.zamaz.mcp.security.model.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Custom OAuth2 user service that handles user creation and mapping from OAuth2 providers.
 * Supports Google, Microsoft, GitHub, and custom OIDC providers.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class OAuth2UserService extends DefaultOAuth2UserService {

    private final SecurityAuditLogger auditLogger;
    private final EmailService emailService;
    
    // In-memory user storage for demonstration (replace with database in production)
    private final Map<String, McpUser> userStorage = new ConcurrentHashMap<>();

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        try {
            OAuth2User oauth2User = super.loadUser(userRequest);
            
            String registrationId = userRequest.getClientRegistration().getRegistrationId();
            log.info("Processing OAuth2 user from provider: {}", registrationId);
            
            // Extract user information based on provider
            UserInfo userInfo = extractUserInfo(oauth2User, registrationId);
            
            // Find or create user
            McpUser user = findOrCreateUser(userInfo, registrationId);
            
            // Update last login information
            updateUserLoginInfo(user, userRequest);
            
            // Log successful authentication
            auditLogger.logSecurityEvent(
                SecurityAuditLogger.SecurityEventType.OAUTH2_LOGIN_SUCCESS,
                SecurityAuditLogger.RiskLevel.LOW,
                "OAuth2 login successful",
                Map.of(
                    "provider", registrationId,
                    "userId", user.getId(),
                    "email", user.getEmail()
                )
            );
            
            return new OAuth2UserPrincipal(user, oauth2User.getAttributes());
            
        } catch (Exception e) {
            log.error("OAuth2 authentication failed", e);
            
            auditLogger.logSecurityEvent(
                SecurityAuditLogger.SecurityEventType.OAUTH2_LOGIN_FAILED,
                SecurityAuditLogger.RiskLevel.MEDIUM,
                "OAuth2 login failed",
                Map.of(
                    "provider", userRequest.getClientRegistration().getRegistrationId(),
                    "error", e.getMessage()
                )
            );
            
            throw new OAuth2AuthenticationException("OAuth2 authentication failed: " + e.getMessage());
        }
    }

    /**
     * Extract user information from OAuth2 user based on provider.
     */
    private UserInfo extractUserInfo(OAuth2User oauth2User, String registrationId) {
        Map<String, Object> attributes = oauth2User.getAttributes();
        
        return switch (registrationId.toLowerCase()) {
            case "google" -> extractGoogleUserInfo(attributes);
            case "microsoft" -> extractMicrosoftUserInfo(attributes);
            case "github" -> extractGitHubUserInfo(attributes);
            case "custom" -> extractCustomUserInfo(attributes);
            default -> throw new OAuth2AuthenticationException("Unsupported OAuth2 provider: " + registrationId);
        };
    }

    /**
     * Extract user information from Google OAuth2 response.
     */
    private UserInfo extractGoogleUserInfo(Map<String, Object> attributes) {
        return UserInfo.builder()
            .providerId((String) attributes.get("sub"))
            .email((String) attributes.get("email"))
            .firstName((String) attributes.get("given_name"))
            .lastName((String) attributes.get("family_name"))
            .fullName((String) attributes.get("name"))
            .profilePicture((String) attributes.get("picture"))
            .emailVerified(Boolean.TRUE.equals(attributes.get("email_verified")))
            .provider("google")
            .build();
    }

    /**
     * Extract user information from Microsoft OAuth2 response.
     */
    private UserInfo extractMicrosoftUserInfo(Map<String, Object> attributes) {
        return UserInfo.builder()
            .providerId((String) attributes.get("sub"))
            .email((String) attributes.get("email"))
            .firstName((String) attributes.get("given_name"))
            .lastName((String) attributes.get("family_name"))
            .fullName((String) attributes.get("name"))
            .emailVerified(true) // Microsoft emails are considered verified
            .provider("microsoft")
            .build();
    }

    /**
     * Extract user information from GitHub OAuth2 response.
     */
    private UserInfo extractGitHubUserInfo(Map<String, Object> attributes) {
        String fullName = (String) attributes.get("name");
        String[] nameParts = fullName != null ? fullName.split(" ", 2) : new String[]{"", ""};
        
        return UserInfo.builder()
            .providerId(String.valueOf(attributes.get("id")))
            .email((String) attributes.get("email"))
            .firstName(nameParts.length > 0 ? nameParts[0] : "")
            .lastName(nameParts.length > 1 ? nameParts[1] : "")
            .fullName(fullName)
            .profilePicture((String) attributes.get("avatar_url"))
            .emailVerified(true) // GitHub emails are considered verified
            .provider("github")
            .build();
    }

    /**
     * Extract user information from custom OIDC provider response.
     */
    private UserInfo extractCustomUserInfo(Map<String, Object> attributes) {
        return UserInfo.builder()
            .providerId((String) attributes.get("sub"))
            .email((String) attributes.get("email"))
            .firstName((String) attributes.get("given_name"))
            .lastName((String) attributes.get("family_name"))
            .fullName((String) attributes.get("name"))
            .emailVerified(Boolean.TRUE.equals(attributes.get("email_verified")))
            .provider("custom")
            .build();
    }

    /**
     * Find existing user or create new user from OAuth2 information.
     */
    private McpUser findOrCreateUser(UserInfo userInfo, String provider) {
        // Try to find existing user by email
        McpUser existingUser = findUserByEmail(userInfo.getEmail());
        
        if (existingUser != null) {
            log.info("Found existing user for email: {}", userInfo.getEmail());
            
            // Update user with OAuth2 information if needed
            updateUserFromOAuth2(existingUser, userInfo, provider);
            return existingUser;
        }
        
        // Create new user
        log.info("Creating new user from OAuth2 provider: {}", provider);
        return createUserFromOAuth2(userInfo, provider);
    }

    /**
     * Find user by email address.
     */
    private McpUser findUserByEmail(String email) {
        return userStorage.values().stream()
            .filter(user -> email.equals(user.getEmail()))
            .findFirst()
            .orElse(null);
    }

    /**
     * Create new user from OAuth2 information.
     */
    private McpUser createUserFromOAuth2(UserInfo userInfo, String provider) {
        McpUser user = new McpUser();
        user.setId(UUID.randomUUID().toString());
        user.setEmail(userInfo.getEmail());
        user.setFirstName(userInfo.getFirstName());
        user.setLastName(userInfo.getLastName());
        user.setEmailVerified(userInfo.isEmailVerified());
        user.setEnabled(true);
        user.setCreatedAt(new Date());
        user.setUpdatedAt(new Date());
        
        // Set username as email for OAuth2 users
        user.setUsername(userInfo.getEmail());
        
        // OAuth2 users don't have passwords
        user.setPassword(null);
        
        // Accept terms and privacy policy automatically for OAuth2 users
        user.acceptTerms();
        user.acceptPrivacyPolicy();
        
        // Add default user role
        Role userRole = new Role();
        userRole.setName("USER");
        user.getGlobalRoles().add(userRole);
        
        // Store OAuth2 provider information
        user.setRoles(List.of("ROLE_USER", "OAUTH2_" + provider.toUpperCase()));
        
        // Default organization (in production, this would be configured)
        user.setOrganizationIds(List.of("default-org"));
        
        // Store user
        userStorage.put(user.getId(), user);
        
        // Send welcome email
        try {
            emailService.sendWelcomeEmail(user.getEmail(), user.getFirstName());
        } catch (Exception e) {
            log.error("Failed to send welcome email to OAuth2 user", e);
        }
        
        log.info("Created new OAuth2 user: {} from provider: {}", user.getId(), provider);
        return user;
    }

    /**
     * Update existing user with OAuth2 information.
     */
    private void updateUserFromOAuth2(McpUser user, UserInfo userInfo, String provider) {
        boolean updated = false;
        
        // Update first name if not set
        if ((user.getFirstName() == null || user.getFirstName().trim().isEmpty()) 
            && userInfo.getFirstName() != null) {
            user.setFirstName(userInfo.getFirstName());
            updated = true;
        }
        
        // Update last name if not set
        if ((user.getLastName() == null || user.getLastName().trim().isEmpty()) 
            && userInfo.getLastName() != null) {
            user.setLastName(userInfo.getLastName());
            updated = true;
        }
        
        // Update email verification status
        if (userInfo.isEmailVerified() && !user.isEmailVerified()) {
            user.setEmailVerified(true);
            updated = true;
        }
        
        // Add OAuth2 provider role if not present
        String providerRole = "OAUTH2_" + provider.toUpperCase();
        if (!user.getRoles().contains(providerRole)) {
            user.getRoles().add(providerRole);
            updated = true;
        }
        
        if (updated) {
            user.setUpdatedAt(new Date());
            userStorage.put(user.getId(), user);
            log.debug("Updated existing user: {} with OAuth2 information", user.getId());
        }
    }

    /**
     * Update user login information.
     */
    private void updateUserLoginInfo(McpUser user, OAuth2UserRequest userRequest) {
        user.setLastLoginAt(new Date());
        user.setUpdatedAt(new Date());
        userStorage.put(user.getId(), user);
    }

    /**
     * User information extracted from OAuth2 provider.
     */
    private static class UserInfo {
        private final String providerId;
        private final String email;
        private final String firstName;
        private final String lastName;
        private final String fullName;
        private final String profilePicture;
        private final boolean emailVerified;
        private final String provider;

        private UserInfo(Builder builder) {
            this.providerId = builder.providerId;
            this.email = builder.email;
            this.firstName = builder.firstName;
            this.lastName = builder.lastName;
            this.fullName = builder.fullName;
            this.profilePicture = builder.profilePicture;
            this.emailVerified = builder.emailVerified;
            this.provider = builder.provider;
        }

        public static Builder builder() {
            return new Builder();
        }

        public String getProviderId() { return providerId; }
        public String getEmail() { return email; }
        public String getFirstName() { return firstName; }
        public String getLastName() { return lastName; }
        public String getFullName() { return fullName; }
        public String getProfilePicture() { return profilePicture; }
        public boolean isEmailVerified() { return emailVerified; }
        public String getProvider() { return provider; }

        public static class Builder {
            private String providerId;
            private String email;
            private String firstName;
            private String lastName;
            private String fullName;
            private String profilePicture;
            private boolean emailVerified;
            private String provider;

            public Builder providerId(String providerId) { this.providerId = providerId; return this; }
            public Builder email(String email) { this.email = email; return this; }
            public Builder firstName(String firstName) { this.firstName = firstName; return this; }
            public Builder lastName(String lastName) { this.lastName = lastName; return this; }
            public Builder fullName(String fullName) { this.fullName = fullName; return this; }
            public Builder profilePicture(String profilePicture) { this.profilePicture = profilePicture; return this; }
            public Builder emailVerified(boolean emailVerified) { this.emailVerified = emailVerified; return this; }
            public Builder provider(String provider) { this.provider = provider; return this; }

            public UserInfo build() {
                return new UserInfo(this);
            }
        }
    }
}