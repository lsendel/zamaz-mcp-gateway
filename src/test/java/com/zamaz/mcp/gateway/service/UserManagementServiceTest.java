package com.zamaz.mcp.gateway.service;

import com.zamaz.mcp.gateway.dto.*;
import com.zamaz.mcp.gateway.exception.UserManagementException;
import com.zamaz.mcp.security.model.McpUser;
import com.zamaz.mcp.security.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive tests for UserManagementService
 */
@ExtendWith(MockitoExtension.class)
class UserManagementServiceTest {

    @Mock
    private PasswordEncoder passwordEncoder;
    
    @Mock
    private EmailService emailService;
    
    @Mock
    private JwtService jwtService;

    @InjectMocks
    private UserManagementService userManagementService;

    private UserRegistrationRequest validRegistrationRequest;
    private McpUser mockUser;

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

        mockUser = new McpUser();
        mockUser.setId("user-123");
        mockUser.setEmail("john.doe@example.com");
        mockUser.setFirstName("John");
        mockUser.setLastName("Doe");
        mockUser.setPassword("encoded-password");
        mockUser.setEnabled(true);
        mockUser.setEmailVerified(false);
        mockUser.setCreatedAt(new Date());
        mockUser.setOrganizationIds(List.of("org-123"));
    }

    @Test
    void registerUser_WithValidRequest_ShouldSucceed() {
        // Arrange
        when(passwordEncoder.encode(anyString())).thenReturn("encoded-password");
        doNothing().when(emailService).sendEmailVerification(anyString(), anyString(), anyString());

        // Act
        UserRegistrationResponse response = userManagementService.registerUser(validRegistrationRequest);

        // Assert
        assertNotNull(response);
        assertNotNull(response.getUserId());
        assertEquals(validRegistrationRequest.getEmail(), response.getEmail());
        assertTrue(response.isVerificationRequired());
        assertEquals("Registration successful. Please check your email to verify your account.", response.getMessage());
        
        verify(passwordEncoder).encode(validRegistrationRequest.getPassword());
        verify(emailService).sendEmailVerification(eq(validRegistrationRequest.getEmail()), eq(validRegistrationRequest.getFirstName()), anyString());
    }

    @Test
    void registerUser_WithDuplicateEmail_ShouldThrowException() {
        // Arrange
        userManagementService.registerUser(validRegistrationRequest);

        // Act & Assert
        UserManagementException exception = assertThrows(UserManagementException.class, () -> {
            userManagementService.registerUser(validRegistrationRequest);
        });

        assertEquals("Email address is already registered", exception.getMessage());
    }

    @Test
    void registerUser_WithInvalidPassword_ShouldThrowException() {
        // Arrange
        validRegistrationRequest.setPassword("weak");

        // Act & Assert
        UserManagementException exception = assertThrows(UserManagementException.class, () -> {
            userManagementService.registerUser(validRegistrationRequest);
        });

        assertTrue(exception.getMessage().contains("Password must"));
    }

    @Test
    void registerUser_WithoutTermsAcceptance_ShouldThrowException() {
        // Arrange
        validRegistrationRequest.setAcceptTerms(false);

        // Act & Assert
        UserManagementException exception = assertThrows(UserManagementException.class, () -> {
            userManagementService.registerUser(validRegistrationRequest);
        });

        assertEquals("Terms and conditions must be accepted", exception.getMessage());
    }

    @Test
    void registerUser_WithoutPrivacyPolicyAcceptance_ShouldThrowException() {
        // Arrange
        validRegistrationRequest.setAcceptPrivacyPolicy(false);

        // Act & Assert
        UserManagementException exception = assertThrows(UserManagementException.class, () -> {
            userManagementService.registerUser(validRegistrationRequest);
        });

        assertEquals("Privacy policy must be accepted", exception.getMessage());
    }

    @Test
    void verifyEmail_WithValidToken_ShouldSucceed() {
        // Arrange
        String token = "valid-token";
        mockUser.setEmailVerificationToken(token);
        mockUser.setEmailVerificationTokenExpiresAt(new Date(System.currentTimeMillis() + 3600000)); // 1 hour from now
        
        doNothing().when(emailService).sendWelcomeEmail(anyString(), anyString());

        // Act
        EmailVerificationResponse response = userManagementService.verifyEmail(token);

        // Assert
        assertNotNull(response);
        assertEquals("Email verified successfully", response.getMessage());
        assertTrue(response.isVerified());
        assertTrue(mockUser.isEmailVerified());
        assertNull(mockUser.getEmailVerificationToken());
        
        verify(emailService).sendWelcomeEmail(mockUser.getEmail(), mockUser.getFirstName());
    }

    @Test
    void verifyEmail_WithInvalidToken_ShouldThrowException() {
        // Arrange
        String invalidToken = "invalid-token";

        // Act & Assert
        UserManagementException exception = assertThrows(UserManagementException.class, () -> {
            userManagementService.verifyEmail(invalidToken);
        });

        assertEquals("Invalid or expired verification token", exception.getMessage());
    }

    @Test
    void verifyEmail_WithExpiredToken_ShouldThrowException() {
        // Arrange
        String expiredToken = "expired-token";
        mockUser.setEmailVerificationToken(expiredToken);
        mockUser.setEmailVerificationTokenExpiresAt(new Date(System.currentTimeMillis() - 3600000)); // 1 hour ago

        // Act & Assert
        UserManagementException exception = assertThrows(UserManagementException.class, () -> {
            userManagementService.verifyEmail(expiredToken);
        });

        assertEquals("Invalid or expired verification token", exception.getMessage());
    }

    @Test
    void initiatePasswordReset_WithValidEmail_ShouldSucceed() {
        // Arrange
        String email = "john.doe@example.com";
        doNothing().when(emailService).sendPasswordReset(anyString(), anyString(), anyString());

        // Act
        PasswordResetResponse response = userManagementService.initiatePasswordReset(email);

        // Assert
        assertNotNull(response);
        assertEquals("If the email address exists in our system, a password reset link has been sent.", response.getMessage());
        
        verify(emailService).sendPasswordReset(eq(email), eq(mockUser.getFirstName()), anyString());
    }

    @Test
    void initiatePasswordReset_WithNonExistentEmail_ShouldNotRevealExistence() {
        // Arrange
        String nonExistentEmail = "nonexistent@example.com";

        // Act
        PasswordResetResponse response = userManagementService.initiatePasswordReset(nonExistentEmail);

        // Assert
        assertNotNull(response);
        assertEquals("If the email address exists in our system, a password reset link has been sent.", response.getMessage());
        
        verify(emailService, never()).sendPasswordReset(anyString(), anyString(), anyString());
    }

    @Test
    void resetPassword_WithValidToken_ShouldSucceed() {
        // Arrange
        String token = "valid-reset-token";
        String newPassword = "NewSecurePassword456!";
        
        mockUser.setPasswordResetToken(token);
        mockUser.setPasswordResetTokenExpiresAt(new Date(System.currentTimeMillis() + 3600000)); // 1 hour from now
        
        when(passwordEncoder.encode(newPassword)).thenReturn("new-encoded-password");

        // Act
        PasswordResetResponse response = userManagementService.resetPassword(token, newPassword);

        // Assert
        assertNotNull(response);
        assertEquals("Password reset successfully", response.getMessage());
        assertEquals("new-encoded-password", mockUser.getPassword());
        assertNull(mockUser.getPasswordResetToken());
        assertNull(mockUser.getPasswordResetTokenExpiresAt());
        
        verify(passwordEncoder).encode(newPassword);
    }

    @Test
    void resetPassword_WithInvalidToken_ShouldThrowException() {
        // Arrange
        String invalidToken = "invalid-token";
        String newPassword = "NewSecurePassword456!";

        // Act & Assert
        UserManagementException exception = assertThrows(UserManagementException.class, () -> {
            userManagementService.resetPassword(invalidToken, newPassword);
        });

        assertEquals("Invalid or expired password reset token", exception.getMessage());
    }

    @Test
    void resetPassword_WithWeakPassword_ShouldThrowException() {
        // Arrange
        String token = "valid-reset-token";
        String weakPassword = "weak";
        
        mockUser.setPasswordResetToken(token);
        mockUser.setPasswordResetTokenExpiresAt(new Date(System.currentTimeMillis() + 3600000));

        // Act & Assert
        UserManagementException exception = assertThrows(UserManagementException.class, () -> {
            userManagementService.resetPassword(token, weakPassword);
        });

        assertTrue(exception.getMessage().contains("Password must"));
    }

    @Test
    void getUserProfile_WithValidUserId_ShouldReturnProfile() {
        // Arrange
        String userId = "user-123";

        // Act
        UserProfileResponse response = userManagementService.getUserProfile(userId);

        // Assert
        assertNotNull(response);
        assertEquals(mockUser.getId(), response.getUserId());
        assertEquals(mockUser.getEmail(), response.getEmail());
        assertEquals(mockUser.getFirstName(), response.getFirstName());
        assertEquals(mockUser.getLastName(), response.getLastName());
        assertEquals(mockUser.isEmailVerified(), response.isEmailVerified());
        assertEquals(mockUser.getCreatedAt(), response.getCreatedAt());
    }

    @Test
    void getUserProfile_WithInvalidUserId_ShouldThrowException() {
        // Arrange
        String invalidUserId = "invalid-user-id";

        // Act & Assert
        UserManagementException exception = assertThrows(UserManagementException.class, () -> {
            userManagementService.getUserProfile(invalidUserId);
        });

        assertEquals("User not found", exception.getMessage());
    }

    @Test
    void updateUserProfile_WithValidData_ShouldSucceed() {
        // Arrange
        String userId = "user-123";
        UserProfileUpdateRequest request = UserProfileUpdateRequest.builder()
                .firstName("Jane")
                .lastName("Smith")
                .build();

        // Act
        UserProfileResponse response = userManagementService.updateUserProfile(userId, request);

        // Assert
        assertNotNull(response);
        assertEquals("Jane", response.getFirstName());
        assertEquals("Smith", response.getLastName());
        assertEquals("Jane", mockUser.getFirstName());
        assertEquals("Smith", mockUser.getLastName());
    }

    @Test
    void changePassword_WithValidCurrentPassword_ShouldSucceed() {
        // Arrange
        String userId = "user-123";
        String currentPassword = "CurrentPassword123!";
        String newPassword = "NewPassword456!";
        
        PasswordChangeRequest request = PasswordChangeRequest.builder()
                .currentPassword(currentPassword)
                .newPassword(newPassword)
                .confirmPassword(newPassword)
                .build();

        when(passwordEncoder.matches(currentPassword, mockUser.getPassword())).thenReturn(true);
        when(passwordEncoder.encode(newPassword)).thenReturn("new-encoded-password");

        // Act
        PasswordChangeResponse response = userManagementService.changePassword(userId, request);

        // Assert
        assertNotNull(response);
        assertEquals("Password changed successfully", response.getMessage());
        assertEquals("new-encoded-password", mockUser.getPassword());
        
        verify(passwordEncoder).matches(currentPassword, "encoded-password");
        verify(passwordEncoder).encode(newPassword);
    }

    @Test
    void changePassword_WithIncorrectCurrentPassword_ShouldThrowException() {
        // Arrange
        String userId = "user-123";
        String incorrectPassword = "WrongPassword123!";
        String newPassword = "NewPassword456!";
        
        PasswordChangeRequest request = PasswordChangeRequest.builder()
                .currentPassword(incorrectPassword)
                .newPassword(newPassword)
                .confirmPassword(newPassword)
                .build();

        when(passwordEncoder.matches(incorrectPassword, mockUser.getPassword())).thenReturn(false);

        // Act & Assert
        UserManagementException exception = assertThrows(UserManagementException.class, () -> {
            userManagementService.changePassword(userId, request);
        });

        assertEquals("Current password is incorrect", exception.getMessage());
    }

    @Test
    void changePassword_WithMismatchedConfirmation_ShouldThrowException() {
        // Arrange
        String userId = "user-123";
        String currentPassword = "CurrentPassword123!";
        String newPassword = "NewPassword456!";
        String wrongConfirmation = "DifferentPassword789!";
        
        PasswordChangeRequest request = PasswordChangeRequest.builder()
                .currentPassword(currentPassword)
                .newPassword(newPassword)
                .confirmPassword(wrongConfirmation)
                .build();

        // Act & Assert
        UserManagementException exception = assertThrows(UserManagementException.class, () -> {
            userManagementService.changePassword(userId, request);
        });

        assertEquals("New password and confirmation do not match", exception.getMessage());
    }

    @Test
    void deactivateAccount_WithValidUserId_ShouldSucceed() {
        // Arrange
        String userId = "user-123";
        String reason = "User requested account deletion";
        
        doNothing().when(emailService).sendAccountDeactivationNotification(anyString(), anyString());

        // Act
        AccountDeactivationResponse response = userManagementService.deactivateAccount(userId, reason);

        // Assert
        assertNotNull(response);
        assertEquals("Account has been deactivated successfully", response.getMessage());
        assertNotNull(response.getDeactivatedAt());
        assertTrue(mockUser.isDeactivated());
        assertEquals(reason, mockUser.getDeactivationReason());
        assertFalse(mockUser.isEnabled());
        
        verify(emailService).sendAccountDeactivationNotification(mockUser.getEmail(), mockUser.getFirstName());
    }

    @Test
    void validatePassword_WithValidPassword_ShouldPass() {
        // Arrange
        String validPassword = "SecurePassword123!";

        // Act & Assert
        assertDoesNotThrow(() -> {
            userManagementService.validatePassword(validPassword);
        });
    }

    @Test
    void validatePassword_WithShortPassword_ShouldThrowException() {
        // Arrange
        String shortPassword = "Short1!";

        // Act & Assert
        UserManagementException exception = assertThrows(UserManagementException.class, () -> {
            userManagementService.validatePassword(shortPassword);
        });

        assertEquals("Password must be at least 8 characters long", exception.getMessage());
    }

    @Test
    void validatePassword_WithoutUppercase_ShouldThrowException() {
        // Arrange
        String passwordWithoutUppercase = "lowercase123!";

        // Act & Assert
        UserManagementException exception = assertThrows(UserManagementException.class, () -> {
            userManagementService.validatePassword(passwordWithoutUppercase);
        });

        assertEquals("Password must contain at least one uppercase letter", exception.getMessage());
    }

    @Test
    void validatePassword_WithoutLowercase_ShouldThrowException() {
        // Arrange
        String passwordWithoutLowercase = "UPPERCASE123!";

        // Act & Assert
        UserManagementException exception = assertThrows(UserManagementException.class, () -> {
            userManagementService.validatePassword(passwordWithoutLowercase);
        });

        assertEquals("Password must contain at least one lowercase letter", exception.getMessage());
    }

    @Test
    void validatePassword_WithoutNumbers_ShouldThrowException() {
        // Arrange
        String passwordWithoutNumbers = "NoNumbers!";

        // Act & Assert
        UserManagementException exception = assertThrows(UserManagementException.class, () -> {
            userManagementService.validatePassword(passwordWithoutNumbers);
        });

        assertEquals("Password must contain at least one number", exception.getMessage());
    }

    @Test
    void validatePassword_WithoutSpecialChars_ShouldThrowException() {
        // Arrange
        String passwordWithoutSpecialChars = "NoSpecialChars123";

        // Act & Assert
        UserManagementException exception = assertThrows(UserManagementException.class, () -> {
            userManagementService.validatePassword(passwordWithoutSpecialChars);
        });

        assertEquals("Password must contain at least one special character", exception.getMessage());
    }

    @Test
    void validateEmail_WithValidEmail_ShouldPass() {
        // Arrange
        String validEmail = "user@example.com";

        // Act & Assert
        assertDoesNotThrow(() -> {
            userManagementService.validateEmail(validEmail);
        });
    }

    @Test
    void validateEmail_WithInvalidEmail_ShouldThrowException() {
        // Arrange
        String invalidEmail = "invalid-email";

        // Act & Assert
        UserManagementException exception = assertThrows(UserManagementException.class, () -> {
            userManagementService.validateEmail(invalidEmail);
        });

        assertEquals("Invalid email format", exception.getMessage());
    }

    @Test
    void generateEmailVerificationToken_ShouldReturnValidToken() {
        // Arrange
        String email = "test@example.com";

        // Act
        String token = userManagementService.generateEmailVerificationToken(email);

        // Assert
        assertNotNull(token);
        assertFalse(token.isEmpty());
        assertTrue(token.length() >= 32); // Should be a secure token
    }

    @Test
    void generatePasswordResetToken_ShouldReturnValidToken() {
        // Arrange
        String email = "test@example.com";

        // Act
        String token = userManagementService.generatePasswordResetToken(email);

        // Assert
        assertNotNull(token);
        assertFalse(token.isEmpty());
        assertTrue(token.length() >= 32); // Should be a secure token
    }
}