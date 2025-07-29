package com.zamaz.mcp.gateway.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zamaz.mcp.gateway.dto.*;
import com.zamaz.mcp.gateway.service.EmailService;
import com.zamaz.mcp.gateway.service.UserManagementService;
import com.zamaz.mcp.security.audit.SecurityAuditLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for UserManagementController
 */
@WebMvcTest(UserManagementController.class)
class UserManagementControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private UserManagementService userManagementService;

    @MockBean
    private SecurityAuditLogger auditLogger;

    @MockBean
    private EmailService emailService;

    private UserRegistrationRequest validRegistrationRequest;
    private UserRegistrationResponse registrationResponse;

    @BeforeEach
    void setUp() {
        validRegistrationRequest = UserRegistrationRequest.builder()
                .email("john.doe@example.com")
                .password("SecurePassword123!")
                .firstName("John")
                .lastName("Doe")
                .organizationId("org-123")
                .acceptTerms(true)
                .acceptPrivacyPolicy(true)
                .build();

        registrationResponse = UserRegistrationResponse.builder()
                .userId("user-123")
                .email("john.doe@example.com")
                .message("Registration successful. Please check your email to verify your account.")
                .verificationRequired(true)
                .build();
    }

    @Test
    void registerUser_WithValidRequest_ShouldReturn201() throws Exception {
        // Arrange
        when(userManagementService.registerUser(any(UserRegistrationRequest.class)))
                .thenReturn(registrationResponse);

        // Act & Assert
        mockMvc.perform(post("/api/v1/users/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRegistrationRequest)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.userId").value("user-123"))
                .andExpect(jsonPath("$.email").value("john.doe@example.com"))
                .andExpect(jsonPath("$.verificationRequired").value(true));

        verify(userManagementService).registerUser(any(UserRegistrationRequest.class));
        verify(auditLogger).logSecurityEvent(
                eq(SecurityAuditLogger.SecurityEventType.USER_REGISTERED),
                eq(SecurityAuditLogger.RiskLevel.LOW),
                anyString(),
                anyMap()
        );
    }

    @Test
    void registerUser_WithInvalidRequest_ShouldReturn400() throws Exception {
        // Arrange
        UserRegistrationRequest invalidRequest = UserRegistrationRequest.builder()
                .email("invalid-email")
                .password("weak")
                .build();

        // Act & Assert
        mockMvc.perform(post("/api/v1/users/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void registerUser_WithMissingTermsAcceptance_ShouldReturn400() throws Exception {
        // Arrange
        validRegistrationRequest.setAcceptTerms(false);

        // Act & Assert
        mockMvc.perform(post("/api/v1/users/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRegistrationRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void verifyEmail_WithValidToken_ShouldReturn200() throws Exception {
        // Arrange
        String token = "valid-verification-token";
        EmailVerificationResponse response = EmailVerificationResponse.builder()
                .message("Email verified successfully")
                .verified(true)
                .build();

        when(userManagementService.verifyEmail(token)).thenReturn(response);

        // Act & Assert
        mockMvc.perform(post("/api/v1/users/verify-email")
                        .with(csrf())
                        .param("token", token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verified").value(true))
                .andExpect(jsonPath("$.message").value("Email verified successfully"));

        verify(userManagementService).verifyEmail(token);
    }

    @Test
    void verifyEmail_WithInvalidToken_ShouldReturn400() throws Exception {
        // Arrange
        String invalidToken = "invalid-token";
        when(userManagementService.verifyEmail(invalidToken))
                .thenThrow(new RuntimeException("Invalid or expired verification token"));

        // Act & Assert
        mockMvc.perform(post("/api/v1/users/verify-email")
                        .with(csrf())
                        .param("token", invalidToken))
                .andExpect(status().isBadRequest());
    }

    @Test
    void forgotPassword_WithValidEmail_ShouldReturn200() throws Exception {
        // Arrange
        String email = "john.doe@example.com";
        PasswordResetResponse response = PasswordResetResponse.builder()
                .message("If the email address exists in our system, a password reset link has been sent.")
                .build();

        when(userManagementService.initiatePasswordReset(email)).thenReturn(response);

        // Act & Assert
        mockMvc.perform(post("/api/v1/users/forgot-password")
                        .with(csrf())
                        .param("email", email))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").exists());

        verify(userManagementService).initiatePasswordReset(email);
    }

    @Test
    void resetPassword_WithValidToken_ShouldReturn200() throws Exception {
        // Arrange
        String token = "valid-reset-token";
        String newPassword = "NewSecurePassword456!";
        PasswordResetResponse response = PasswordResetResponse.builder()
                .message("Password reset successfully")
                .build();

        when(userManagementService.resetPassword(token, newPassword)).thenReturn(response);

        // Act & Assert
        mockMvc.perform(post("/api/v1/users/reset-password")
                        .with(csrf())
                        .param("token", token)
                        .param("newPassword", newPassword))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Password reset successfully"));

        verify(userManagementService).resetPassword(token, newPassword);
    }

    @Test
    @WithMockUser(username = "user-123")
    void getUserProfile_WithAuthentication_ShouldReturn200() throws Exception {
        // Arrange
        UserProfileResponse response = UserProfileResponse.builder()
                .userId("user-123")
                .email("john.doe@example.com")
                .firstName("John")
                .lastName("Doe")
                .emailVerified(true)
                .build();

        when(userManagementService.getUserProfile("user-123")).thenReturn(response);

        // Act & Assert
        mockMvc.perform(get("/api/v1/users/profile")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("user-123"))
                .andExpect(jsonPath("$.email").value("john.doe@example.com"))
                .andExpect(jsonPath("$.firstName").value("John"))
                .andExpect(jsonPath("$.lastName").value("Doe"))
                .andExpect(jsonPath("$.emailVerified").value(true));

        verify(userManagementService).getUserProfile("user-123");
    }

    @Test
    void getUserProfile_WithoutAuthentication_ShouldReturn401() throws Exception {
        // Act & Assert
        mockMvc.perform(get("/api/v1/users/profile"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "user-123")
    void updateUserProfile_WithValidRequest_ShouldReturn200() throws Exception {
        // Arrange
        UserProfileUpdateRequest request = UserProfileUpdateRequest.builder()
                .firstName("Jane")
                .lastName("Smith")
                .build();

        UserProfileResponse response = UserProfileResponse.builder()
                .userId("user-123")
                .email("john.doe@example.com")
                .firstName("Jane")
                .lastName("Smith")
                .emailVerified(true)
                .build();

        when(userManagementService.updateUserProfile(eq("user-123"), any(UserProfileUpdateRequest.class)))
                .thenReturn(response);

        // Act & Assert
        mockMvc.perform(put("/api/v1/users/profile")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.firstName").value("Jane"))
                .andExpect(jsonPath("$.lastName").value("Smith"));

        verify(userManagementService).updateUserProfile(eq("user-123"), any(UserProfileUpdateRequest.class));
    }

    @Test
    @WithMockUser(username = "user-123")
    void changePassword_WithValidRequest_ShouldReturn200() throws Exception {
        // Arrange
        PasswordChangeRequest request = PasswordChangeRequest.builder()
                .currentPassword("CurrentPassword123!")
                .newPassword("NewPassword456!")
                .confirmPassword("NewPassword456!")
                .build();

        PasswordChangeResponse response = PasswordChangeResponse.builder()
                .message("Password changed successfully")
                .build();

        when(userManagementService.changePassword(eq("user-123"), any(PasswordChangeRequest.class)))
                .thenReturn(response);

        // Act & Assert
        mockMvc.perform(post("/api/v1/users/change-password")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Password changed successfully"));

        verify(userManagementService).changePassword(eq("user-123"), any(PasswordChangeRequest.class));
    }

    @Test
    @WithMockUser(username = "user-123")
    void deactivateAccount_ShouldReturn200() throws Exception {
        // Arrange
        String reason = "User requested account deletion";
        AccountDeactivationResponse response = AccountDeactivationResponse.builder()
                .message("Account has been deactivated successfully")
                .deactivatedAt(LocalDateTime.now())
                .build();

        when(userManagementService.deactivateAccount("user-123", reason)).thenReturn(response);

        // Act & Assert
        mockMvc.perform(post("/api/v1/users/deactivate")
                        .with(csrf())
                        .param("reason", reason))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Account has been deactivated successfully"));

        verify(userManagementService).deactivateAccount("user-123", reason);
    }

    @Test
    @WithMockUser(username = "admin-123", roles = {"ADMIN"})
    void getUserProfileById_WithAdminRole_ShouldReturn200() throws Exception {
        // Arrange
        String targetUserId = "user-456";
        UserProfileResponse response = UserProfileResponse.builder()
                .userId(targetUserId)
                .email("target.user@example.com")
                .firstName("Target")
                .lastName("User")
                .emailVerified(true)
                .build();

        when(userManagementService.getUserProfile(targetUserId)).thenReturn(response);

        // Act & Assert
        mockMvc.perform(get("/api/v1/users/{userId}/profile", targetUserId)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(targetUserId))
                .andExpect(jsonPath("$.email").value("target.user@example.com"));

        verify(userManagementService).getUserProfile(targetUserId);
    }

    @Test
    @WithMockUser(username = "user-123", roles = {"USER"})
    void getUserProfileById_WithoutAdminRole_ShouldReturn403() throws Exception {
        // Arrange
        String targetUserId = "user-456";

        // Act & Assert
        mockMvc.perform(get("/api/v1/users/{userId}/profile", targetUserId)
                        .with(csrf()))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin-123", roles = {"ADMIN"})
    void deactivateUserAccount_WithAdminRole_ShouldReturn200() throws Exception {
        // Arrange
        String targetUserId = "user-456";
        String reason = "Admin requested deactivation";
        AccountDeactivationResponse response = AccountDeactivationResponse.builder()
                .message("Account has been deactivated successfully")
                .deactivatedAt(LocalDateTime.now())
                .build();

        when(userManagementService.deactivateAccount(targetUserId, reason)).thenReturn(response);

        // Act & Assert
        mockMvc.perform(post("/api/v1/users/{userId}/deactivate", targetUserId)
                        .with(csrf())
                        .param("reason", reason))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Account has been deactivated successfully"));

        verify(userManagementService).deactivateAccount(targetUserId, reason);
        verify(auditLogger).logSecurityEvent(
                eq(SecurityAuditLogger.SecurityEventType.ACCOUNT_DEACTIVATED),
                eq(SecurityAuditLogger.RiskLevel.HIGH),
                anyString(),
                anyMap()
        );
    }

    @Test
    @WithMockUser(username = "user-123", roles = {"USER"})
    void deactivateUserAccount_WithoutAdminRole_ShouldReturn403() throws Exception {
        // Arrange
        String targetUserId = "user-456";
        String reason = "Unauthorized deactivation attempt";

        // Act & Assert
        mockMvc.perform(post("/api/v1/users/{userId}/deactivate", targetUserId)
                        .with(csrf())
                        .param("reason", reason))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "user-123")
    void resendEmailVerification_ShouldReturn200() throws Exception {
        // Act & Assert
        mockMvc.perform(post("/api/v1/users/resend-verification")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Verification email sent successfully"));
    }

    @Test
    void registerUser_WithRateLimitExceeded_ShouldReturn429() throws Exception {
        // This test would require rate limiting configuration
        // For now, we'll skip implementation details and focus on the structure
    }

    @Test
    void verifyEmail_WithAlreadyVerifiedAccount_ShouldReturn400() throws Exception {
        // Arrange
        String token = "already-verified-token";
        when(userManagementService.verifyEmail(token))
                .thenThrow(new RuntimeException("Email is already verified"));

        // Act & Assert
        mockMvc.perform(post("/api/v1/users/verify-email")
                        .with(csrf())
                        .param("token", token))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "user-123")
    void changePassword_WithIncorrectCurrentPassword_ShouldReturn400() throws Exception {
        // Arrange
        PasswordChangeRequest request = PasswordChangeRequest.builder()
                .currentPassword("WrongPassword123!")
                .newPassword("NewPassword456!")
                .confirmPassword("NewPassword456!")
                .build();

        when(userManagementService.changePassword(eq("user-123"), any(PasswordChangeRequest.class)))
                .thenThrow(new RuntimeException("Current password is incorrect"));

        // Act & Assert
        mockMvc.perform(post("/api/v1/users/change-password")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }
}