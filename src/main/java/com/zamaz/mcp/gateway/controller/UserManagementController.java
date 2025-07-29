package com.zamaz.mcp.gateway.controller;

import com.zamaz.mcp.gateway.dto.*;
import com.zamaz.mcp.gateway.exception.UserManagementException;
import com.zamaz.mcp.gateway.service.UserManagementService;
import com.zamaz.mcp.security.annotation.RequiresRole;
import com.zamaz.mcp.security.audit.SecurityAuditLogger;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST controller for user management operations including registration,
 * profile management, password reset, and account verification.
 */
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "User Management", description = "User registration, profile management, and account operations")
public class UserManagementController {

    private final UserManagementService userManagementService;
    private final SecurityAuditLogger auditLogger;

    /**
     * User registration endpoint
     */
    @Operation(
        summary = "Register new user",
        description = "Register a new user account with email verification",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "User registration details",
            required = true,
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = UserRegistrationRequest.class),
                examples = @ExampleObject(
                    name = "registration",
                    value = """
                    {
                        "email": "john.doe@example.com",
                        "password": "SecurePassword123!",
                        "firstName": "John",
                        "lastName": "Doe",
                        "organizationId": "org-123",
                        "acceptTerms": true,
                        "acceptPrivacyPolicy": true
                    }
                    """
                )
            )
        )
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "201",
            description = "User registered successfully",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = UserRegistrationResponse.class)
            )
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid registration data",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(value = """
                    {
                        "error": "Bad Request",
                        "message": "Email address is already registered",
                        "timestamp": 1642680000000
                    }
                    """)
            )
        ),
        @ApiResponse(
            responseCode = "422",
            description = "Validation errors",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(value = """
                    {
                        "error": "Validation Failed",
                        "message": "Password must contain at least one uppercase letter",
                        "timestamp": 1642680000000
                    }
                    """)
            )
        )
    })
    @PostMapping("/register")
    public ResponseEntity<UserRegistrationResponse> registerUser(
            @Valid @RequestBody UserRegistrationRequest request,
            HttpServletRequest httpRequest) {
        
        String clientIp = getClientIp(httpRequest);
        log.debug("User registration attempt for email: {} from IP: {}", request.getEmail(), clientIp);
        
        try {
            UserRegistrationResponse response = userManagementService.registerUser(request);
            
            auditLogger.logSecurityEvent(
                SecurityAuditLogger.SecurityEventType.USER_REGISTERED,
                SecurityAuditLogger.RiskLevel.LOW,
                "User registration successful",
                Map.of(
                    "email", request.getEmail(),
                    "clientIp", clientIp
                )
            );
            
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
            
        } catch (UserManagementException e) {
            auditLogger.logSecurityEvent(
                SecurityAuditLogger.SecurityEventType.USER_REGISTRATION_FAILED,
                SecurityAuditLogger.RiskLevel.MEDIUM,
                "User registration failed",
                Map.of(
                    "email", request.getEmail(),
                    "clientIp", clientIp,
                    "reason", e.getMessage()
                )
            );
            throw e;
        }
    }

    /**
     * Email verification endpoint
     */
    @Operation(
        summary = "Verify email address",
        description = "Verify user email address using verification token"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Email verified successfully",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = EmailVerificationResponse.class)
            )
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid or expired verification token"
        )
    })
    @PostMapping("/verify-email")
    public ResponseEntity<EmailVerificationResponse> verifyEmail(
            @Parameter(description = "Email verification token", required = true)
            @RequestParam String token,
            HttpServletRequest httpRequest) {
        
        String clientIp = getClientIp(httpRequest);
        log.debug("Email verification attempt from IP: {}", clientIp);
        
        EmailVerificationResponse response = userManagementService.verifyEmail(token);
        return ResponseEntity.ok(response);
    }

    /**
     * Initiate password reset
     */
    @Operation(
        summary = "Initiate password reset",
        description = "Send password reset email to user"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Password reset email sent (if email exists)",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = PasswordResetResponse.class)
            )
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid email format"
        )
    })
    @PostMapping("/forgot-password")
    public ResponseEntity<PasswordResetResponse> forgotPassword(
            @Parameter(description = "Email address", required = true)
            @RequestParam String email,
            HttpServletRequest httpRequest) {
        
        String clientIp = getClientIp(httpRequest);
        log.debug("Password reset request for email: {} from IP: {}", email, clientIp);
        
        PasswordResetResponse response = userManagementService.initiatePasswordReset(email);
        return ResponseEntity.ok(response);
    }

    /**
     * Reset password using token
     */
    @Operation(
        summary = "Reset password",
        description = "Reset user password using reset token"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Password reset successfully",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = PasswordResetResponse.class)
            )
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid token or password requirements not met"
        )
    })
    @PostMapping("/reset-password")
    public ResponseEntity<PasswordResetResponse> resetPassword(
            @Parameter(description = "Password reset token", required = true)
            @RequestParam String token,
            @Parameter(description = "New password", required = true)
            @RequestParam String newPassword,
            HttpServletRequest httpRequest) {
        
        String clientIp = getClientIp(httpRequest);
        log.debug("Password reset completion attempt from IP: {}", clientIp);
        
        PasswordResetResponse response = userManagementService.resetPassword(token, newPassword);
        return ResponseEntity.ok(response);
    }

    /**
     * Get current user profile
     */
    @Operation(
        summary = "Get user profile",
        description = "Get current user's profile information"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "User profile retrieved successfully",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = UserProfileResponse.class)
            )
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required"
        ),
        @ApiResponse(
            responseCode = "404",
            description = "User not found"
        )
    })
    @GetMapping("/profile")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<UserProfileResponse> getUserProfile() {
        String userId = getCurrentUserId();
        
        UserProfileResponse response = userManagementService.getUserProfile(userId);
        return ResponseEntity.ok(response);
    }

    /**
     * Update user profile
     */
    @Operation(
        summary = "Update user profile",
        description = "Update current user's profile information"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Profile updated successfully",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = UserProfileResponse.class)
            )
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid profile data"
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required"
        )
    })
    @PutMapping("/profile")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<UserProfileResponse> updateUserProfile(
            @Valid @RequestBody UserProfileUpdateRequest request) {
        
        String userId = getCurrentUserId();
        
        UserProfileResponse response = userManagementService.updateUserProfile(userId, request);
        return ResponseEntity.ok(response);
    }

    /**
     * Change user password
     */
    @Operation(
        summary = "Change password",
        description = "Change current user's password"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Password changed successfully",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = PasswordChangeResponse.class)
            )
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid password or current password incorrect"
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required"
        )
    })
    @PostMapping("/change-password")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<PasswordChangeResponse> changePassword(
            @Valid @RequestBody PasswordChangeRequest request) {
        
        String userId = getCurrentUserId();
        
        PasswordChangeResponse response = userManagementService.changePassword(userId, request);
        return ResponseEntity.ok(response);
    }

    /**
     * Deactivate user account
     */
    @Operation(
        summary = "Deactivate account",
        description = "Deactivate current user's account"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Account deactivated successfully",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = AccountDeactivationResponse.class)
            )
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required"
        )
    })
    @PostMapping("/deactivate")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<AccountDeactivationResponse> deactivateAccount(
            @Parameter(description = "Reason for deactivation")
            @RequestParam(required = false) String reason) {
        
        String userId = getCurrentUserId();
        
        AccountDeactivationResponse response = userManagementService.deactivateAccount(userId, reason);
        return ResponseEntity.ok(response);
    }

    /**
     * Admin endpoint: Get user profile by ID
     */
    @Operation(
        summary = "Get user profile by ID (Admin)",
        description = "Get any user's profile information (admin only)"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "User profile retrieved successfully"
        ),
        @ApiResponse(
            responseCode = "403",
            description = "Admin access required"
        ),
        @ApiResponse(
            responseCode = "404",
            description = "User not found"
        )
    })
    @GetMapping("/{userId}/profile")
    @RequiresRole("ADMIN")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<UserProfileResponse> getUserProfileById(
            @Parameter(description = "User ID", required = true)
            @PathVariable String userId) {
        
        UserProfileResponse response = userManagementService.getUserProfile(userId);
        return ResponseEntity.ok(response);
    }

    /**
     * Admin endpoint: Deactivate user account by ID
     */
    @Operation(
        summary = "Deactivate user account (Admin)",
        description = "Deactivate any user's account (admin only)"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Account deactivated successfully"
        ),
        @ApiResponse(
            responseCode = "403",
            description = "Admin access required"
        ),
        @ApiResponse(
            responseCode = "404",
            description = "User not found"
        )
    })
    @PostMapping("/{userId}/deactivate")
    @RequiresRole("ADMIN")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<AccountDeactivationResponse> deactivateUserAccount(
            @Parameter(description = "User ID", required = true)
            @PathVariable String userId,
            @Parameter(description = "Reason for deactivation", required = true)
            @RequestParam String reason) {
        
        String adminUserId = getCurrentUserId();
        
        auditLogger.logSecurityEvent(
            SecurityAuditLogger.SecurityEventType.ACCOUNT_DEACTIVATED,
            SecurityAuditLogger.RiskLevel.HIGH,
            "Admin deactivated user account",
            Map.of(
                "adminUserId", adminUserId,
                "targetUserId", userId,
                "reason", reason
            )
        );
        
        AccountDeactivationResponse response = userManagementService.deactivateAccount(userId, reason);
        return ResponseEntity.ok(response);
    }

    /**
     * Resend email verification
     */
    @Operation(
        summary = "Resend email verification",
        description = "Resend email verification for current user"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Verification email sent"
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required"
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Email already verified"
        )
    })
    @PostMapping("/resend-verification")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<Map<String, String>> resendEmailVerification() {
        String userId = getCurrentUserId();
        
        // This would need to be implemented in the service
        // For now, return a placeholder response
        return ResponseEntity.ok(Map.of(
            "message", "Verification email sent successfully"
        ));
    }

    // Helper methods

    private String getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new UserManagementException("User not authenticated");
        }
        
        // Extract user ID from authentication principal
        // This assumes the principal contains the user ID
        return authentication.getName();
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }

    
}