package com.zamaz.mcp.gateway.service;

import com.zamaz.mcp.gateway.dto.*;
import com.zamaz.mcp.gateway.exception.AuthenticationException;
import com.zamaz.mcp.security.jwt.JwtService;
import com.zamaz.mcp.security.model.McpUser;
import com.zamaz.mcp.security.service.UserDetailsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Service for handling authentication operations.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final UserDetailsService userDetailsService;
    private final UserService userService;
    private final OrganizationService organizationService;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RedisTemplate<String, Object> redisTemplate;

    private static final String REFRESH_TOKEN_PREFIX = "refresh_token:";
    private static final String BLACKLIST_TOKEN_PREFIX = "blacklist_token:";
    private static final String RESET_TOKEN_PREFIX = "reset_token:";
    private static final long REFRESH_TOKEN_VALIDITY = 7 * 24 * 60 * 60 * 1000; // 7 days
    private static final long RESET_TOKEN_VALIDITY = 1 * 60 * 60 * 1000; // 1 hour

    /**
     * Authenticate user and generate tokens.
     */
    @Transactional
    public AuthResponse authenticate(String username, String password, String organizationId) {
        log.debug("Authenticating user: {}", username);
        
        // Load user by username or email
        McpUser user = userDetailsService.loadUserByUsername(username);
        if (user == null) {
            user = userDetailsService.loadUserByEmail(username);
        }
        
        if (user == null) {
            throw new AuthenticationException("Invalid credentials");
        }
        
        // Verify password
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new AuthenticationException("Invalid credentials");
        }
        
        // Check if account is enabled
        if (!user.isEnabled()) {
            throw new AuthenticationException("Account is disabled");
        }
        
        // Check if account is locked
        if (!user.isAccountNonLocked()) {
            throw new AuthenticationException("Account is locked");
        }
        
        // Set organization context if provided
        if (organizationId != null) {
            if (!user.getOrganizationIds().contains(organizationId)) {
                throw new AuthenticationException("User does not belong to the specified organization");
            }
            user.setCurrentOrganizationId(organizationId);
        } else if (user.getCurrentOrganizationId() == null && !user.getOrganizationIds().isEmpty()) {
            // Set first organization as default
            user.setCurrentOrganizationId(user.getOrganizationIds().iterator().next());
        }
        
        // Update last login
        userDetailsService.updateLastLogin(user.getId(), getClientIp());
        
        // Generate tokens
        String accessToken = jwtService.generateToken(user);
        String refreshToken = generateRefreshToken(user.getId());
        
        return buildAuthResponse(user, accessToken, refreshToken);
    }

    /**
     * Register new user.
     */
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        log.debug("Registering new user: {}", request.getUsername());
        
        // Check if username already exists
        if (userDetailsService.loadUserByUsername(request.getUsername()) != null) {
            throw new AuthenticationException("Username already exists");
        }
        
        // Check if email already exists
        if (userDetailsService.loadUserByEmail(request.getEmail()) != null) {
            throw new AuthenticationException("Email already exists");
        }
        
        // Create new user
        McpUser user = new McpUser();
        user.setId(UUID.randomUUID().toString());
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEnabled(true);
        user.setCreatedAt(new Date());
        
        // Handle organization
        String organizationId;
        if (request.getOrganizationId() != null) {
            // Join existing organization
            organizationId = request.getOrganizationId();
            if (!organizationService.exists(organizationId)) {
                throw new AuthenticationException("Organization not found");
            }
        } else if (request.getOrganizationName() != null) {
            // Create new organization
            organizationId = organizationService.create(request.getOrganizationName(), user.getId());
        } else {
            // Create default personal organization
            organizationId = organizationService.create(
                user.getUsername() + "'s Organization", 
                user.getId()
            );
        }
        
        // Set organization
        user.setOrganizationIds(Collections.singletonList(organizationId));
        user.setCurrentOrganizationId(organizationId);
        
        // Save user
        userService.save(user);
        
        // Add user to organization
        organizationService.addMember(organizationId, user.getId(), "MEMBER");
        
        // Generate tokens
        String accessToken = jwtService.generateToken(user);
        String refreshToken = generateRefreshToken(user.getId());
        
        return buildAuthResponse(user, accessToken, refreshToken);
    }

    /**
     * Refresh access token.
     */
    public AuthResponse refreshToken(String refreshToken) {
        log.debug("Refreshing access token");
        
        // Validate refresh token
        String userId = validateRefreshToken(refreshToken);
        if (userId == null) {
            throw new AuthenticationException("Invalid refresh token");
        }
        
        // Load user
        McpUser user = userDetailsService.loadUserById(userId);
        if (user == null || !user.isEnabled()) {
            throw new AuthenticationException("User not found or disabled");
        }
        
        // Generate new access token
        String newAccessToken = jwtService.generateToken(user);
        
        return buildAuthResponse(user, newAccessToken, refreshToken);
    }

    /**
     * Logout user.
     */
    public void logout(String token) {
        log.debug("Logging out user");
        
        // Add token to blacklist
        String key = BLACKLIST_TOKEN_PREFIX + token;
        Date expiration = jwtService.extractExpiration(token);
        long ttl = expiration.getTime() - System.currentTimeMillis();
        
        if (ttl > 0) {
            redisTemplate.opsForValue().set(key, true, ttl, TimeUnit.MILLISECONDS);
        }
        
        // Remove refresh token
        String userId = jwtService.extractUserId(token);
        String refreshKey = REFRESH_TOKEN_PREFIX + userId;
        redisTemplate.delete(refreshKey);
    }

    /**
     * Initiate password reset.
     */
    @Transactional
    public void initiatePasswordReset(String email) {
        log.debug("Initiating password reset for: {}", email);
        
        McpUser user = userDetailsService.loadUserByEmail(email);
        if (user == null) {
            // Don't reveal if email exists
            return;
        }
        
        // Generate reset token
        String resetToken = UUID.randomUUID().toString();
        String key = RESET_TOKEN_PREFIX + resetToken;
        
        redisTemplate.opsForValue().set(
            key, 
            user.getId(), 
            RESET_TOKEN_VALIDITY, 
            TimeUnit.MILLISECONDS
        );
        
        // Send email (implement email service)
        // emailService.sendPasswordResetEmail(user.getEmail(), resetToken);
        
        log.info("Password reset token generated for user: {}", user.getId());
    }

    /**
     * Reset password.
     */
    @Transactional
    public void resetPassword(String token, String newPassword) {
        log.debug("Resetting password");
        
        // Validate reset token
        String key = RESET_TOKEN_PREFIX + token;
        String userId = (String) redisTemplate.opsForValue().get(key);
        
        if (userId == null) {
            throw new AuthenticationException("Invalid or expired reset token");
        }
        
        // Load user
        McpUser user = userDetailsService.loadUserById(userId);
        if (user == null) {
            throw new AuthenticationException("User not found");
        }
        
        // Update password
        user.setPassword(passwordEncoder.encode(newPassword));
        userService.save(user);
        
        // Delete reset token
        redisTemplate.delete(key);
        
        // Invalidate all existing tokens
        String blacklistKey = BLACKLIST_TOKEN_PREFIX + "user:" + userId + ":*";
        redisTemplate.delete(blacklistKey);
        
        log.info("Password reset for user: {}", userId);
    }

    /**
     * Validate token.
     */
    public TokenValidationResponse validateToken(String token) {
        try {
            // Check if token is blacklisted
            String blacklistKey = BLACKLIST_TOKEN_PREFIX + token;
            if (Boolean.TRUE.equals(redisTemplate.hasKey(blacklistKey))) {
                return TokenValidationResponse.builder()
                    .valid(false)
                    .error("Token is blacklisted")
                    .build();
            }
            
            // Validate token
            if (!jwtService.isTokenValid(token)) {
                return TokenValidationResponse.builder()
                    .valid(false)
                    .error("Invalid token")
                    .build();
            }
            
            // Extract token info
            String userId = jwtService.extractUserId(token);
            String username = jwtService.extractUsername(token);
            String organizationId = jwtService.extractOrganizationId(token);
            Date expiration = jwtService.extractExpiration(token);
            long expiresIn = (expiration.getTime() - System.currentTimeMillis()) / 1000;
            
            return TokenValidationResponse.builder()
                .valid(true)
                .userId(userId)
                .username(username)
                .organizationId(organizationId)
                .expiresIn(expiresIn)
                .build();
                
        } catch (Exception e) {
            return TokenValidationResponse.builder()
                .valid(false)
                .error(e.getMessage())
                .build();
        }
    }

    /**
     * Get current user info.
     */
    public UserInfoResponse getCurrentUser(String token) {
        String userId = jwtService.extractUserId(token);
        McpUser user = userDetailsService.loadUserById(userId);
        
        if (user == null) {
            throw new AuthenticationException("User not found");
        }
        
        return buildUserInfoResponse(user);
    }

    /**
     * Switch organization context.
     */
    @Transactional
    public AuthResponse switchOrganization(String token, String organizationId) {
        String userId = jwtService.extractUserId(token);
        McpUser user = userDetailsService.loadUserById(userId);
        
        if (user == null) {
            throw new AuthenticationException("User not found");
        }
        
        if (!user.getOrganizationIds().contains(organizationId)) {
            throw new AuthenticationException("User does not belong to the specified organization");
        }
        
        // Update current organization
        user.setCurrentOrganizationId(organizationId);
        userService.save(user);
        
        // Generate new tokens with updated organization context
        String newAccessToken = jwtService.generateToken(user);
        String refreshToken = generateRefreshToken(user.getId());
        
        return buildAuthResponse(user, newAccessToken, refreshToken);
    }

    /**
     * Generate refresh token.
     */
    private String generateRefreshToken(String userId) {
        String refreshToken = UUID.randomUUID().toString();
        String key = REFRESH_TOKEN_PREFIX + userId;
        
        redisTemplate.opsForValue().set(
            key, 
            refreshToken, 
            REFRESH_TOKEN_VALIDITY, 
            TimeUnit.MILLISECONDS
        );
        
        return refreshToken;
    }

    /**
     * Validate refresh token.
     */
    private String validateRefreshToken(String refreshToken) {
        // Search for the refresh token in Redis
        Set<String> keys = redisTemplate.keys(REFRESH_TOKEN_PREFIX + "*");
        if (keys != null) {
            for (String key : keys) {
                String storedToken = (String) redisTemplate.opsForValue().get(key);
                if (refreshToken.equals(storedToken)) {
                    return key.substring(REFRESH_TOKEN_PREFIX.length());
                }
            }
        }
        return null;
    }

    /**
     * Build authentication response.
     */
    private AuthResponse buildAuthResponse(McpUser user, String accessToken, String refreshToken) {
        // Get organization info
        List<AuthResponse.OrganizationInfo> organizations = user.getOrganizationIds().stream()
            .map(orgId -> {
                String orgName = organizationService.getName(orgId);
                String role = organizationService.getUserRole(orgId, user.getId());
                return AuthResponse.OrganizationInfo.builder()
                    .id(orgId)
                    .name(orgName)
                    .role(role)
                    .build();
            })
            .collect(Collectors.toList());
        
        // Get roles and permissions for current organization
        Set<String> roles = user.getOrganizationRoles(user.getCurrentOrganizationId())
            .stream()
            .map(r -> r.getName())
            .collect(Collectors.toSet());
        
        Set<String> permissions = user.getAllPermissions(user.getCurrentOrganizationId())
            .stream()
            .map(p -> p.getName())
            .collect(Collectors.toSet());
        
        AuthResponse.UserInfo userInfo = AuthResponse.UserInfo.builder()
            .id(user.getId())
            .username(user.getUsername())
            .email(user.getEmail())
            .firstName(user.getFirstName())
            .lastName(user.getLastName())
            .currentOrganizationId(user.getCurrentOrganizationId())
            .organizations(organizations)
            .roles(roles)
            .permissions(permissions)
            .build();
        
        return AuthResponse.builder()
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .tokenType("Bearer")
            .expiresIn(jwtService.getExpirationTime() / 1000) // Convert to seconds
            .user(userInfo)
            .build();
    }

    /**
     * Build user info response.
     */
    private UserInfoResponse buildUserInfoResponse(McpUser user) {
        // Get organization memberships
        List<UserInfoResponse.OrganizationMembership> memberships = user.getOrganizationIds().stream()
            .map(orgId -> {
                Set<String> orgRoles = user.getOrganizationRoles(orgId)
                    .stream()
                    .map(r -> r.getName())
                    .collect(Collectors.toSet());
                
                return UserInfoResponse.OrganizationMembership.builder()
                    .organizationId(orgId)
                    .organizationName(organizationService.getName(orgId))
                    .roles(orgRoles)
                    .joinedAt(organizationService.getMemberJoinDate(orgId, user.getId()))
                    .isDefault(orgId.equals(user.getCurrentOrganizationId()))
                    .build();
            })
            .collect(Collectors.toList());
        
        // Get global roles and permissions
        Set<String> globalRoles = user.getGlobalRoles()
            .stream()
            .map(r -> r.getName())
            .collect(Collectors.toSet());
        
        Set<String> globalPermissions = user.getGlobalPermissions()
            .stream()
            .map(p -> p.getName())
            .collect(Collectors.toSet());
        
        // Get current org roles and permissions
        Set<String> currentOrgRoles = user.getOrganizationRoles(user.getCurrentOrganizationId())
            .stream()
            .map(r -> r.getName())
            .collect(Collectors.toSet());
        
        Set<String> currentOrgPermissions = user.getOrganizationPermissions(user.getCurrentOrganizationId())
            .stream()
            .map(p -> p.getName())
            .collect(Collectors.toSet());
        
        return UserInfoResponse.builder()
            .id(user.getId())
            .username(user.getUsername())
            .email(user.getEmail())
            .firstName(user.getFirstName())
            .lastName(user.getLastName())
            .enabled(user.isEnabled())
            .createdAt(user.getCreatedAt())
            .lastLoginAt(user.getLastLoginAt())
            .currentOrganizationId(user.getCurrentOrganizationId())
            .organizations(memberships)
            .globalRoles(globalRoles)
            .globalPermissions(globalPermissions)
            .currentOrgRoles(currentOrgRoles)
            .currentOrgPermissions(currentOrgPermissions)
            .build();
    }

    /**
     * Get client IP (placeholder - implement based on your needs).
     */
    private String getClientIp() {
        // This should be implemented to get the actual client IP from the request
        return "0.0.0.0";
    }
}