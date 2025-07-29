package com.zamaz.mcp.gateway.service;

import com.zamaz.mcp.gateway.dto.*;
import com.zamaz.mcp.security.model.McpUser;
import com.zamaz.mcp.security.audit.SecurityAuditLogger;
import com.zamaz.mcp.gateway.exception.UserManagementException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Comprehensive user management service handling registration, profile management,
 * password reset, email verification, and account management.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserManagementService {

    private final PasswordEncoder passwordEncoder;
    private final SecurityAuditLogger auditLogger;
    private final RedisTemplate<String, Object> redisTemplate;
    private final EmailService emailService;
    
    @Value("${app.user-management.password-reset-expiry:3600}")
    private int passwordResetExpirySeconds;
    
    @Value("${app.user-management.email-verification-expiry:86400}")
    private int emailVerificationExpirySeconds;
    
    @Value("${app.user-management.max-login-attempts:5}")
    private int maxLoginAttempts;
    
    @Value("${app.user-management.account-lockout-duration:1800}")
    private int accountLockoutDurationSeconds;
    
    // Password policy constants
    private static final int MIN_PASSWORD_LENGTH = 8;
    private static final int MAX_PASSWORD_LENGTH = 128;
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
        "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{"
        + MIN_PASSWORD_LENGTH + "," + MAX_PASSWORD_LENGTH + "}$"
    );
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
        "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    );
    
    // Redis key prefixes
    private static final String PASSWORD_RESET_KEY_PREFIX = "password_reset:";
    private static final String EMAIL_VERIFICATION_KEY_PREFIX = "email_verification:";
    private static final String LOGIN_ATTEMPTS_KEY_PREFIX = "login_attempts:";
    private static final String ACCOUNT_LOCKOUT_KEY_PREFIX = "account_lockout:";
    private static final String USERS_KEY_PREFIX = "users:";

    /**
     * Register a new user with email verification
     */
    public UserRegistrationResponse registerUser(UserRegistrationRequest request) {
        log.info("Starting user registration for email: {}", request.getEmail());
        
        // Validate registration request
        validateRegistrationRequest(request);
        
        // Check if user already exists
        if (userExists(request.getEmail())) {
            auditLogger.logSecurityEvent(
                SecurityAuditLogger.SecurityEventType.USER_REGISTRATION_FAILED,
                SecurityAuditLogger.RiskLevel.MEDIUM,
                "User registration attempt with existing email",
                Map.of("email", request.getEmail(), "reason", "email_already_exists")
            );
            throw new UserManagementException("Email address is already registered");
        }
        
        // Create user account
        McpUser user = createUserAccount(request);
        
        // Store user in Redis (temporary until database integration)
        storeUser(user);
        
        // Generate email verification token
        String verificationToken = generateEmailVerificationToken(user.getEmail());
        
        // Send verification email
        sendVerificationEmail(user, verificationToken);
        
        auditLogger.logSecurityEvent(
            SecurityAuditLogger.SecurityEventType.USER_REGISTERED,
            SecurityAuditLogger.RiskLevel.LOW,
            "New user registered successfully",
            Map.of(
                "userId", user.getId(),
                "email", user.getEmail(),
                "organizationId", user.getCurrentOrganizationId()
            )
        );
        
        return UserRegistrationResponse.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .message("Registration successful. Please check your email to verify your account.")
                .verificationRequired(true)
                .build();
    }
    
    /**
     * Verify user email address
     */
    public EmailVerificationResponse verifyEmail(String token) {
        log.info("Processing email verification for token");
        
        if (!StringUtils.hasText(token)) {
            throw new UserManagementException("Verification token is required");
        }
        
        // Validate verification token
        String email = validateEmailVerificationToken(token);
        if (email == null) {
            auditLogger.logSecurityEvent(
                SecurityAuditLogger.SecurityEventType.EMAIL_VERIFICATION_FAILED,
                SecurityAuditLogger.RiskLevel.MEDIUM,
                "Email verification failed with invalid token",
                Map.of("token", token.substring(0, Math.min(8, token.length())) + "...")
            );
            throw new UserManagementException("Invalid or expired verification token");
        }
        
        // Update user verification status
        McpUser user = getUser(email);
        if (user == null) {
            throw new UserManagementException("User not found");
        }
        
        user.setEmailVerified(true);
        user.setEnabled(true);
        storeUser(user);
        
        // Remove verification token
        redisTemplate.delete(EMAIL_VERIFICATION_KEY_PREFIX + token);
        
        auditLogger.logSecurityEvent(
            SecurityAuditLogger.SecurityEventType.EMAIL_VERIFIED,
            SecurityAuditLogger.RiskLevel.LOW,
            "Email verification completed successfully",
            Map.of("userId", user.getId(), "email", user.getEmail())
        );
        
        return EmailVerificationResponse.builder()
                .email(user.getEmail())
                .verified(true)
                .message("Email verified successfully. You can now log in to your account.")
                .build();
    }
    
    /**
     * Initiate password reset process
     */
    public PasswordResetResponse initiatePasswordReset(String email) {
        log.info("Initiating password reset for email: {}", email);
        
        if (!StringUtils.hasText(email) || !EMAIL_PATTERN.matcher(email).matches()) {
            throw new UserManagementException("Valid email address is required");
        }
        
        // Check if user exists (but don't reveal if they don't)
        McpUser user = getUser(email);
        boolean userExists = user != null;
        
        if (userExists) {
            // Generate password reset token
            String resetToken = generatePasswordResetToken(email);
            
            // Send password reset email
            sendPasswordResetEmail(user, resetToken);
            
            auditLogger.logSecurityEvent(
                SecurityAuditLogger.SecurityEventType.PASSWORD_RESET_REQUESTED,
                SecurityAuditLogger.RiskLevel.MEDIUM,
                "Password reset requested",
                Map.of("userId", user.getId(), "email", email)
            );
        } else {
            auditLogger.logSecurityEvent(
                SecurityAuditLogger.SecurityEventType.PASSWORD_RESET_REQUESTED,
                SecurityAuditLogger.RiskLevel.LOW,
                "Password reset requested for non-existent user",
                Map.of("email", email)
            );
        }
        
        // Always return the same message for security (don't reveal user existence)
        return PasswordResetResponse.builder()
                .message("If an account with this email exists, a password reset link has been sent.")
                .build();
    }
    
    /**
     * Reset password using reset token
     */
    public PasswordResetResponse resetPassword(String token, String newPassword) {
        log.info("Processing password reset");
        
        if (!StringUtils.hasText(token)) {
            throw new UserManagementException("Reset token is required");
        }
        
        if (!StringUtils.hasText(newPassword)) {
            throw new UserManagementException("New password is required");
        }
        
        // Validate new password
        validatePassword(newPassword);
        
        // Validate reset token
        String email = validatePasswordResetToken(token);
        if (email == null) {
            auditLogger.logSecurityEvent(
                SecurityAuditLogger.SecurityEventType.PASSWORD_RESET_FAILED,
                SecurityAuditLogger.RiskLevel.MEDIUM,
                "Password reset failed with invalid token",
                Map.of("token", token.substring(0, Math.min(8, token.length())) + "...")
            );
            throw new UserManagementException("Invalid or expired reset token");
        }
        
        // Get user and update password
        McpUser user = getUser(email);
        if (user == null) {
            throw new UserManagementException("User not found");
        }
        
        // Update password
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordChangedAt(LocalDateTime.now());
        storeUser(user);
        
        // Remove reset token and clear login attempts
        redisTemplate.delete(PASSWORD_RESET_KEY_PREFIX + token);
        redisTemplate.delete(LOGIN_ATTEMPTS_KEY_PREFIX + email);
        redisTemplate.delete(ACCOUNT_LOCKOUT_KEY_PREFIX + email);
        
        auditLogger.logPasswordChanged();
        auditLogger.logSecurityEvent(
            SecurityAuditLogger.SecurityEventType.PASSWORD_CHANGED,
            SecurityAuditLogger.RiskLevel.MEDIUM,
            "Password reset completed successfully",
            Map.of("userId", user.getId(), "email", email)
        );
        
        return PasswordResetResponse.builder()
                .message("Password reset successfully. You can now log in with your new password.")
                .build();
    }
    
    /**
     * Get user profile information
     */
    public UserProfileResponse getUserProfile(String userId) {
        log.debug("Getting user profile for userId: {}", userId);
        
        McpUser user = getUserById(userId);
        if (user == null) {
            throw new UserManagementException("User not found");
        }
        
        return UserProfileResponse.builder()
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .emailVerified(user.isEmailVerified())
                .enabled(user.isEnabled())
                .createdAt(user.getCreatedAt())
                .lastLoginAt(user.getLastLoginAt())
                .passwordChangedAt(user.getPasswordChangedAt())
                .currentOrganizationId(user.getCurrentOrganizationId())
                .organizations(user.getOrganizations())
                .roles(user.getRoles())
                .build();
    }
    
    /**
     * Update user profile
     */
    public UserProfileResponse updateUserProfile(String userId, UserProfileUpdateRequest request) {
        log.info("Updating user profile for userId: {}", userId);
        
        McpUser user = getUserById(userId);
        if (user == null) {
            throw new UserManagementException("User not found");
        }
        
        boolean emailChanged = false;
        
        // Update profile fields
        if (StringUtils.hasText(request.getFirstName())) {
            user.setFirstName(request.getFirstName().trim());
        }
        
        if (StringUtils.hasText(request.getLastName())) {
            user.setLastName(request.getLastName().trim());
        }
        
        if (StringUtils.hasText(request.getEmail()) && !request.getEmail().equals(user.getEmail())) {
            // Validate new email
            if (!EMAIL_PATTERN.matcher(request.getEmail()).matches()) {
                throw new UserManagementException("Invalid email format");
            }
            
            // Check if email is already taken
            if (userExists(request.getEmail())) {
                throw new UserManagementException("Email address is already in use");
            }
            
            user.setEmail(request.getEmail());
            user.setEmailVerified(false); // Require re-verification
            emailChanged = true;
        }
        
        storeUser(user);
        
        // Send verification email if email changed
        if (emailChanged) {
            String verificationToken = generateEmailVerificationToken(user.getEmail());
            sendVerificationEmail(user, verificationToken);
        }
        
        auditLogger.logSecurityEvent(
            SecurityAuditLogger.SecurityEventType.PROFILE_UPDATED,
            SecurityAuditLogger.RiskLevel.LOW,
            "User profile updated",
            Map.of(
                "userId", user.getId(),
                "emailChanged", String.valueOf(emailChanged)
            )
        );
        
        UserProfileResponse response = getUserProfile(userId);
        if (emailChanged) {
            response.setMessage("Profile updated. Please verify your new email address.");
        }
        
        return response;
    }
    
    /**
     * Change user password
     */
    public PasswordChangeResponse changePassword(String userId, PasswordChangeRequest request) {
        log.info("Processing password change for userId: {}", userId);
        
        McpUser user = getUserById(userId);
        if (user == null) {
            throw new UserManagementException("User not found");
        }
        
        // Verify current password
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            auditLogger.logSecurityEvent(
                SecurityAuditLogger.SecurityEventType.PASSWORD_CHANGE_FAILED,
                SecurityAuditLogger.RiskLevel.MEDIUM,
                "Password change failed - invalid current password",
                Map.of("userId", userId)
            );
            throw new UserManagementException("Current password is incorrect");
        }
        
        // Validate new password
        validatePassword(request.getNewPassword());
        
        // Check if new password is different from current
        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            throw new UserManagementException("New password must be different from current password");
        }
        
        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordChangedAt(LocalDateTime.now());
        storeUser(user);
        
        auditLogger.logPasswordChanged();
        auditLogger.logSecurityEvent(
            SecurityAuditLogger.SecurityEventType.PASSWORD_CHANGED,
            SecurityAuditLogger.RiskLevel.MEDIUM,
            "Password changed successfully",
            Map.of("userId", userId)
        );
        
        return PasswordChangeResponse.builder()
                .message("Password changed successfully")
                .build();
    }
    
    /**
     * Deactivate user account
     */
    public AccountDeactivationResponse deactivateAccount(String userId, String reason) {
        log.info("Deactivating account for userId: {}", userId);
        
        McpUser user = getUserById(userId);
        if (user == null) {
            throw new UserManagementException("User not found");
        }
        
        user.setEnabled(false);
        user.setDeactivatedAt(LocalDateTime.now());
        user.setDeactivationReason(reason);
        storeUser(user);
        
        auditLogger.logSecurityEvent(
            SecurityAuditLogger.SecurityEventType.ACCOUNT_DEACTIVATED,
            SecurityAuditLogger.RiskLevel.MEDIUM,
            "User account deactivated",
            Map.of(
                "userId", userId,
                "reason", reason != null ? reason : "user_requested"
            )
        );
        
        return AccountDeactivationResponse.builder()
                .message("Account deactivated successfully")
                .deactivatedAt(user.getDeactivatedAt())
                .build();
    }
    
    // Private helper methods
    
    private void validateRegistrationRequest(UserRegistrationRequest request) {
        if (!StringUtils.hasText(request.getEmail()) || !EMAIL_PATTERN.matcher(request.getEmail()).matches()) {
            throw new UserManagementException("Valid email address is required");
        }
        
        if (!StringUtils.hasText(request.getPassword())) {
            throw new UserManagementException("Password is required");
        }
        
        validatePassword(request.getPassword());
        
        if (!StringUtils.hasText(request.getFirstName())) {
            throw new UserManagementException("First name is required");
        }
        
        if (!StringUtils.hasText(request.getLastName())) {
            throw new UserManagementException("Last name is required");
        }
    }
    
    private void validatePassword(String password) {
        if (!StringUtils.hasText(password)) {
            throw new UserManagementException("Password is required");
        }
        
        if (password.length() < MIN_PASSWORD_LENGTH) {
            throw new UserManagementException("Password must be at least " + MIN_PASSWORD_LENGTH + " characters long");
        }
        
        if (password.length() > MAX_PASSWORD_LENGTH) {
            throw new UserManagementException("Password must not exceed " + MAX_PASSWORD_LENGTH + " characters");
        }
        
        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            throw new UserManagementException(
                "Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character"
            );
        }
    }
    
    private boolean userExists(String email) {
        return redisTemplate.hasKey(USERS_KEY_PREFIX + "email:" + email);
    }
    
    private McpUser createUserAccount(UserRegistrationRequest request) {
        McpUser user = new McpUser();
        user.setId(UUID.randomUUID().toString());
        user.setUsername(request.getEmail()); // Use email as username
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setFirstName(request.getFirstName().trim());
        user.setLastName(request.getLastName().trim());
        user.setEnabled(false); // Require email verification
        user.setEmailVerified(false);
        user.setCreatedAt(LocalDateTime.now());
        user.setPasswordChangedAt(LocalDateTime.now());
        user.setCurrentOrganizationId(request.getOrganizationId());
        
        // Set default roles
        user.setRoles(List.of("USER"));
        
        return user;
    }
    
    private void storeUser(McpUser user) {
        // Store user by ID
        redisTemplate.opsForValue().set(USERS_KEY_PREFIX + "id:" + user.getId(), user);
        
        // Store user by email for lookup
        redisTemplate.opsForValue().set(USERS_KEY_PREFIX + "email:" + user.getEmail(), user.getId());
    }
    
    private McpUser getUser(String email) {
        String userId = (String) redisTemplate.opsForValue().get(USERS_KEY_PREFIX + "email:" + email);
        if (userId == null) {
            return null;
        }
        
        return (McpUser) redisTemplate.opsForValue().get(USERS_KEY_PREFIX + "id:" + userId);
    }
    
    private McpUser getUserById(String userId) {
        return (McpUser) redisTemplate.opsForValue().get(USERS_KEY_PREFIX + "id:" + userId);
    }
    
    private String generateEmailVerificationToken(String email) {
        String token = UUID.randomUUID().toString();
        redisTemplate.opsForValue().set(
            EMAIL_VERIFICATION_KEY_PREFIX + token,
            email,
            Duration.ofSeconds(emailVerificationExpirySeconds)
        );
        return token;
    }
    
    private String generatePasswordResetToken(String email) {
        String token = UUID.randomUUID().toString();
        redisTemplate.opsForValue().set(
            PASSWORD_RESET_KEY_PREFIX + token,
            email,
            Duration.ofSeconds(passwordResetExpirySeconds)
        );
        return token;
    }
    
    private String validateEmailVerificationToken(String token) {
        return (String) redisTemplate.opsForValue().get(EMAIL_VERIFICATION_KEY_PREFIX + token);
    }
    
    private String validatePasswordResetToken(String token) {
        return (String) redisTemplate.opsForValue().get(PASSWORD_RESET_KEY_PREFIX + token);
    }
    
    private void sendVerificationEmail(McpUser user, String verificationToken) {
        try {
            emailService.sendEmailVerification(user.getEmail(), user.getFirstName(), verificationToken);
        } catch (Exception e) {
            log.error("Failed to send verification email to: {}", user.getEmail(), e);
            // Don't fail the registration process if email sending fails
        }
    }
    
    private void sendPasswordResetEmail(McpUser user, String resetToken) {
        try {
            emailService.sendPasswordReset(user.getEmail(), user.getFirstName(), resetToken);
        } catch (Exception e) {
            log.error("Failed to send password reset email to: {}", user.getEmail(), e);
            // Don't fail the process if email sending fails
        }
    }
}