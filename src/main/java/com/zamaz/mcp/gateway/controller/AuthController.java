package com.zamaz.mcp.gateway.controller;

import com.zamaz.mcp.gateway.dto.*;
import com.zamaz.mcp.gateway.service.AuthenticationService;
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
import org.springframework.web.bind.annotation.*;

/**
 * Authentication controller for handling login, registration, and token management.
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication", description = "User authentication and authorization endpoints")
public class AuthController {

    private final AuthenticationService authenticationService;
    private final SecurityAuditLogger auditLogger;

    /**
     * User login endpoint.
     */
    @Operation(
        summary = "User login",
        description = "Authenticate user with username/email and password. Returns JWT tokens for subsequent API calls.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Login credentials",
            required = true,
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = LoginRequest.class),
                examples = @ExampleObject(
                    name = "login",
                    value = """
                    {
                        "username": "john.doe@example.com",
                        "password": "SecurePassword123!",
                        "organizationId": "org-123"
                    }
                    """
                )
            )
        )
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Login successful",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = AuthResponse.class)
            )
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Invalid credentials",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(value = """
                    {
                        "error": "Unauthorized",
                        "message": "Invalid credentials",
                        "timestamp": 1642680000000
                    }
                    """)
            )
        ),
        @ApiResponse(
            responseCode = "429",
            description = "Too many login attempts",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(value = """
                    {
                        "error": "Too Many Requests",
                        "message": "Rate limit exceeded",
                        "timestamp": 1642680000000
                    }
                    """)
            )
        )
    })
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        
        log.debug("Login attempt for user: {}", request.getUsername());
        String clientIp = getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        
        try {
            AuthResponse response = authenticationService.authenticate(
                request.getUsername(), 
                request.getPassword(), 
                request.getOrganizationId()
            );
            
            auditLogger.logAuthenticationSuccess(clientIp, userAgent);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            auditLogger.logAuthenticationFailure(request.getUsername(), clientIp, e.getMessage());
            throw e;
        }
    }

    /**
     * User registration endpoint.
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {
        
        log.debug("Registration attempt for email: {}", request.getEmail());
        
        AuthResponse response = authenticationService.register(request);
        
        auditLogger.logSecurityEvent(
            SecurityAuditLogger.SecurityEventType.USER_REGISTERED,
            SecurityAuditLogger.RiskLevel.LOW,
            "New user registered",
            java.util.Map.of(
                "email", request.getEmail(),
                "organizationId", request.getOrganizationId()
            )
        );
        
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Token refresh endpoint.
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request) {
        
        log.debug("Token refresh request");
        
        AuthResponse response = authenticationService.refreshToken(request.getRefreshToken());
        
        return ResponseEntity.ok(response);
    }

    /**
     * Logout endpoint.
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestHeader("Authorization") String authHeader,
            HttpServletRequest httpRequest) {
        
        String token = extractToken(authHeader);
        String sessionId = httpRequest.getSession(false) != null ? 
            httpRequest.getSession().getId() : "no-session";
        
        authenticationService.logout(token);
        
        auditLogger.logSessionExpired(sessionId, "USER_LOGOUT");
        
        return ResponseEntity.noContent().build();
    }

    /**
     * Forgot password endpoint.
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<MessageResponse> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request) {
        
        log.debug("Password reset request for email: {}", request.getEmail());
        
        authenticationService.initiatePasswordReset(request.getEmail());
        
        auditLogger.logSecurityEvent(
            SecurityAuditLogger.SecurityEventType.PASSWORD_RESET_REQUESTED,
            SecurityAuditLogger.RiskLevel.MEDIUM,
            "Password reset initiated",
            java.util.Map.of("email", request.getEmail())
        );
        
        return ResponseEntity.ok(new MessageResponse(
            "If the email exists, a password reset link has been sent."
        ));
    }

    /**
     * Reset password endpoint.
     */
    @PostMapping("/reset-password")
    public ResponseEntity<MessageResponse> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request) {
        
        log.debug("Password reset completion attempt");
        
        authenticationService.resetPassword(request.getToken(), request.getNewPassword());
        
        auditLogger.logPasswordChanged();
        
        return ResponseEntity.ok(new MessageResponse("Password has been reset successfully."));
    }

    /**
     * Validate token endpoint.
     */
    @GetMapping("/validate")
    public ResponseEntity<TokenValidationResponse> validateToken(
            @RequestHeader("Authorization") String authHeader) {
        
        String token = extractToken(authHeader);
        TokenValidationResponse response = authenticationService.validateToken(token);
        
        return ResponseEntity.ok(response);
    }

    /**
     * Get current user info.
     */
    @GetMapping("/me")
    public ResponseEntity<UserInfoResponse> getCurrentUser(
            @RequestHeader("Authorization") String authHeader) {
        
        String token = extractToken(authHeader);
        UserInfoResponse response = authenticationService.getCurrentUser(token);
        
        return ResponseEntity.ok(response);
    }

    /**
     * Switch organization context.
     */
    @PostMapping("/switch-organization")
    public ResponseEntity<AuthResponse> switchOrganization(
            @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody SwitchOrganizationRequest request) {
        
        String token = extractToken(authHeader);
        
        AuthResponse response = authenticationService.switchOrganization(
            token, 
            request.getOrganizationId()
        );
        
        auditLogger.logSecurityEvent(
            SecurityAuditLogger.SecurityEventType.ORGANIZATION_SWITCHED,
            SecurityAuditLogger.RiskLevel.LOW,
            "User switched organization context",
            java.util.Map.of(
                "newOrganizationId", request.getOrganizationId()
            )
        );
        
        return ResponseEntity.ok(response);
    }

    /**
     * Extract token from Authorization header.
     */
    private String extractToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        throw new IllegalArgumentException("Invalid authorization header");
    }

    /**
     * Get client IP address.
     */
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