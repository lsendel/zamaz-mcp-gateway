package com.zamaz.mcp.gateway.service;

import com.zamaz.mcp.gateway.dto.*;
import com.zamaz.mcp.gateway.exception.AuthenticationException;
import com.zamaz.mcp.security.jwt.JwtService;
import com.zamaz.mcp.security.model.McpUser;
import com.zamaz.mcp.security.service.UserDetailsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Authentication Service Tests")
class AuthenticationServiceTest {

    @Mock
    private UserDetailsService userDetailsService;
    
    @Mock
    private UserService userService;
    
    @Mock
    private OrganizationService organizationService;
    
    @Mock
    private JwtService jwtService;
    
    @Mock
    private PasswordEncoder passwordEncoder;
    
    @Mock
    private RedisTemplate<String, Object> redisTemplate;
    
    @Mock
    private ValueOperations<String, Object> valueOperations;

    @InjectMocks
    private AuthenticationService authenticationService;

    private McpUser testUser;
    private String testUserId;
    private String testOrgId;
    private String testAccessToken;
    private String testRefreshToken;

    @BeforeEach
    void setUp() {
        testUserId = "user123";
        testOrgId = "org123";
        testAccessToken = "access.token.jwt";
        testRefreshToken = "refresh-token-uuid";
        
        testUser = new McpUser();
        testUser.setId(testUserId);
        testUser.setUsername("testuser");
        testUser.setEmail("test@example.com");
        testUser.setPassword("$2a$10$hashedPassword");
        testUser.setFirstName("Test");
        testUser.setLastName("User");
        testUser.setEnabled(true);
        testUser.setAccountNonLocked(true);
        testUser.setOrganizationIds(Arrays.asList(testOrgId));
        testUser.setCurrentOrganizationId(testOrgId);
        
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    @Nested
    @DisplayName("Authentication Tests")
    class AuthenticationTests {

        @Test
        @DisplayName("Should authenticate user successfully with username")
        void shouldAuthenticateWithUsername() {
            // Given
            String username = "testuser";
            String password = "password123";
            String orgId = testOrgId;
            
            when(userDetailsService.loadUserByUsername(username)).thenReturn(testUser);
            when(passwordEncoder.matches(password, testUser.getPassword())).thenReturn(true);
            when(jwtService.generateToken(testUser)).thenReturn(testAccessToken);
            when(jwtService.getExpirationTime()).thenReturn(86400000L);
            when(organizationService.getName(testOrgId)).thenReturn("Test Org");
            when(organizationService.getUserRole(testOrgId, testUserId)).thenReturn("MEMBER");
            
            // When
            AuthResponse response = authenticationService.authenticate(username, password, orgId);
            
            // Then
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo(testAccessToken);
            assertThat(response.getTokenType()).isEqualTo("Bearer");
            assertThat(response.getUser().getUsername()).isEqualTo(username);
            assertThat(response.getUser().getCurrentOrganizationId()).isEqualTo(orgId);
            
            verify(userDetailsService).updateLastLogin(eq(testUserId), anyString());
            verify(valueOperations).set(anyString(), anyString(), eq(604800000L), eq(TimeUnit.MILLISECONDS));
        }

        @Test
        @DisplayName("Should authenticate user successfully with email")
        void shouldAuthenticateWithEmail() {
            // Given
            String email = "test@example.com";
            String password = "password123";
            
            when(userDetailsService.loadUserByUsername(email)).thenReturn(null);
            when(userDetailsService.loadUserByEmail(email)).thenReturn(testUser);
            when(passwordEncoder.matches(password, testUser.getPassword())).thenReturn(true);
            when(jwtService.generateToken(testUser)).thenReturn(testAccessToken);
            when(jwtService.getExpirationTime()).thenReturn(86400000L);
            when(organizationService.getName(testOrgId)).thenReturn("Test Org");
            when(organizationService.getUserRole(testOrgId, testUserId)).thenReturn("MEMBER");
            
            // When
            AuthResponse response = authenticationService.authenticate(email, password, null);
            
            // Then
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo(testAccessToken);
            verify(userDetailsService).loadUserByUsername(email);
            verify(userDetailsService).loadUserByEmail(email);
        }

        @Test
        @DisplayName("Should throw exception for invalid username")
        void shouldThrowExceptionForInvalidUsername() {
            // Given
            String username = "nonexistent";
            String password = "password123";
            
            when(userDetailsService.loadUserByUsername(username)).thenReturn(null);
            when(userDetailsService.loadUserByEmail(username)).thenReturn(null);
            
            // When & Then
            assertThatThrownBy(() -> authenticationService.authenticate(username, password, null))
                .isInstanceOf(AuthenticationException.class)
                .hasMessage("Invalid credentials");
        }

        @Test
        @DisplayName("Should throw exception for invalid password")
        void shouldThrowExceptionForInvalidPassword() {
            // Given
            String username = "testuser";
            String password = "wrongpassword";
            
            when(userDetailsService.loadUserByUsername(username)).thenReturn(testUser);
            when(passwordEncoder.matches(password, testUser.getPassword())).thenReturn(false);
            
            // When & Then
            assertThatThrownBy(() -> authenticationService.authenticate(username, password, null))
                .isInstanceOf(AuthenticationException.class)
                .hasMessage("Invalid credentials");
        }

        @Test
        @DisplayName("Should throw exception for disabled account")
        void shouldThrowExceptionForDisabledAccount() {
            // Given
            String username = "testuser";
            String password = "password123";
            testUser.setEnabled(false);
            
            when(userDetailsService.loadUserByUsername(username)).thenReturn(testUser);
            when(passwordEncoder.matches(password, testUser.getPassword())).thenReturn(true);
            
            // When & Then
            assertThatThrownBy(() -> authenticationService.authenticate(username, password, null))
                .isInstanceOf(AuthenticationException.class)
                .hasMessage("Account is disabled");
        }

        @Test
        @DisplayName("Should throw exception for locked account")
        void shouldThrowExceptionForLockedAccount() {
            // Given
            String username = "testuser";
            String password = "password123";
            testUser.setAccountNonLocked(false);
            
            when(userDetailsService.loadUserByUsername(username)).thenReturn(testUser);
            when(passwordEncoder.matches(password, testUser.getPassword())).thenReturn(true);
            
            // When & Then
            assertThatThrownBy(() -> authenticationService.authenticate(username, password, null))
                .isInstanceOf(AuthenticationException.class)
                .hasMessage("Account is locked");
        }

        @Test
        @DisplayName("Should throw exception for invalid organization")
        void shouldThrowExceptionForInvalidOrganization() {
            // Given
            String username = "testuser";
            String password = "password123";
            String invalidOrgId = "invalid-org";
            
            when(userDetailsService.loadUserByUsername(username)).thenReturn(testUser);
            when(passwordEncoder.matches(password, testUser.getPassword())).thenReturn(true);
            
            // When & Then
            assertThatThrownBy(() -> authenticationService.authenticate(username, password, invalidOrgId))
                .isInstanceOf(AuthenticationException.class)
                .hasMessage("User does not belong to the specified organization");
        }
    }

    @Nested
    @DisplayName("Registration Tests")
    class RegistrationTests {

        @Test
        @DisplayName("Should register new user successfully")
        void shouldRegisterNewUser() {
            // Given
            RegisterRequest request = RegisterRequest.builder()
                .username("newuser")
                .email("newuser@example.com")
                .password("password123")
                .firstName("New")
                .lastName("User")
                .organizationName("New Org")
                .build();
            
            when(userDetailsService.loadUserByUsername(request.getUsername())).thenReturn(null);
            when(userDetailsService.loadUserByEmail(request.getEmail())).thenReturn(null);
            when(passwordEncoder.encode(request.getPassword())).thenReturn("$2a$10$hashedNewPassword");
            when(organizationService.create(eq("New Org"), anyString())).thenReturn("new-org-id");
            when(jwtService.generateToken(any(McpUser.class))).thenReturn(testAccessToken);
            when(jwtService.getExpirationTime()).thenReturn(86400000L);
            when(organizationService.getName("new-org-id")).thenReturn("New Org");
            when(organizationService.getUserRole(eq("new-org-id"), anyString())).thenReturn("OWNER");
            
            // When
            AuthResponse response = authenticationService.register(request);
            
            // Then
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo(testAccessToken);
            assertThat(response.getUser().getUsername()).isEqualTo("newuser");
            assertThat(response.getUser().getEmail()).isEqualTo("newuser@example.com");
            
            verify(userService).save(any(McpUser.class));
            verify(organizationService).addMember(eq("new-org-id"), anyString(), eq("MEMBER"));
        }

        @Test
        @DisplayName("Should throw exception for existing username")
        void shouldThrowExceptionForExistingUsername() {
            // Given
            RegisterRequest request = RegisterRequest.builder()
                .username("testuser")
                .email("newemail@example.com")
                .password("password123")
                .build();
            
            when(userDetailsService.loadUserByUsername("testuser")).thenReturn(testUser);
            
            // When & Then
            assertThatThrownBy(() -> authenticationService.register(request))
                .isInstanceOf(AuthenticationException.class)
                .hasMessage("Username already exists");
        }

        @Test
        @DisplayName("Should throw exception for existing email")
        void shouldThrowExceptionForExistingEmail() {
            // Given
            RegisterRequest request = RegisterRequest.builder()
                .username("newuser")
                .email("test@example.com")
                .password("password123")
                .build();
            
            when(userDetailsService.loadUserByUsername("newuser")).thenReturn(null);
            when(userDetailsService.loadUserByEmail("test@example.com")).thenReturn(testUser);
            
            // When & Then
            assertThatThrownBy(() -> authenticationService.register(request))
                .isInstanceOf(AuthenticationException.class)
                .hasMessage("Email already exists");
        }

        @Test
        @DisplayName("Should register user with existing organization")
        void shouldRegisterUserWithExistingOrganization() {
            // Given
            RegisterRequest request = RegisterRequest.builder()
                .username("newuser")
                .email("newuser@example.com")
                .password("password123")
                .organizationId(testOrgId)
                .build();
            
            when(userDetailsService.loadUserByUsername("newuser")).thenReturn(null);
            when(userDetailsService.loadUserByEmail("newuser@example.com")).thenReturn(null);
            when(passwordEncoder.encode("password123")).thenReturn("$2a$10$hashedPassword");
            when(organizationService.exists(testOrgId)).thenReturn(true);
            when(jwtService.generateToken(any(McpUser.class))).thenReturn(testAccessToken);
            when(jwtService.getExpirationTime()).thenReturn(86400000L);
            when(organizationService.getName(testOrgId)).thenReturn("Test Org");
            when(organizationService.getUserRole(eq(testOrgId), anyString())).thenReturn("MEMBER");
            
            // When
            AuthResponse response = authenticationService.register(request);
            
            // Then
            assertThat(response).isNotNull();
            assertThat(response.getUser().getCurrentOrganizationId()).isEqualTo(testOrgId);
            verify(organizationService).exists(testOrgId);
            verify(organizationService, never()).create(anyString(), anyString());
        }
    }

    @Nested
    @DisplayName("Token Management Tests")
    class TokenManagementTests {

        @Test
        @DisplayName("Should refresh access token successfully")
        void shouldRefreshAccessToken() {
            // Given
            String refreshToken = "valid-refresh-token";
            
            Set<String> keys = Set.of("refresh_token:" + testUserId);
            when(redisTemplate.keys("refresh_token:*")).thenReturn(keys);
            when(valueOperations.get("refresh_token:" + testUserId)).thenReturn(refreshToken);
            when(userDetailsService.loadUserById(testUserId)).thenReturn(testUser);
            when(jwtService.generateToken(testUser)).thenReturn(testAccessToken);
            when(jwtService.getExpirationTime()).thenReturn(86400000L);
            when(organizationService.getName(testOrgId)).thenReturn("Test Org");
            when(organizationService.getUserRole(testOrgId, testUserId)).thenReturn("MEMBER");
            
            // When
            AuthResponse response = authenticationService.refreshToken(refreshToken);
            
            // Then
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo(testAccessToken);
            assertThat(response.getRefreshToken()).isEqualTo(refreshToken);
        }

        @Test
        @DisplayName("Should throw exception for invalid refresh token")
        void shouldThrowExceptionForInvalidRefreshToken() {
            // Given
            String invalidRefreshToken = "invalid-refresh-token";
            
            when(redisTemplate.keys("refresh_token:*")).thenReturn(Collections.emptySet());
            
            // When & Then
            assertThatThrownBy(() -> authenticationService.refreshToken(invalidRefreshToken))
                .isInstanceOf(AuthenticationException.class)
                .hasMessage("Invalid refresh token");
        }

        @Test
        @DisplayName("Should validate token successfully")
        void shouldValidateTokenSuccessfully() {
            // Given
            String token = "valid.jwt.token";
            Date expiration = new Date(System.currentTimeMillis() + 3600000); // 1 hour
            
            when(redisTemplate.hasKey("blacklist_token:" + token)).thenReturn(false);
            when(jwtService.isTokenValid(token)).thenReturn(true);
            when(jwtService.extractUserId(token)).thenReturn(testUserId);
            when(jwtService.extractUsername(token)).thenReturn("testuser");
            when(jwtService.extractOrganizationId(token)).thenReturn(testOrgId);
            when(jwtService.extractExpiration(token)).thenReturn(expiration);
            
            // When
            TokenValidationResponse response = authenticationService.validateToken(token);
            
            // Then
            assertThat(response.isValid()).isTrue();
            assertThat(response.getUserId()).isEqualTo(testUserId);
            assertThat(response.getUsername()).isEqualTo("testuser");
            assertThat(response.getOrganizationId()).isEqualTo(testOrgId);
            assertThat(response.getExpiresIn()).isGreaterThan(0);
        }

        @Test
        @DisplayName("Should return invalid for blacklisted token")
        void shouldReturnInvalidForBlacklistedToken() {
            // Given
            String token = "blacklisted.jwt.token";
            
            when(redisTemplate.hasKey("blacklist_token:" + token)).thenReturn(true);
            
            // When
            TokenValidationResponse response = authenticationService.validateToken(token);
            
            // Then
            assertThat(response.isValid()).isFalse();
            assertThat(response.getError()).isEqualTo("Token is blacklisted");
        }

        @Test
        @DisplayName("Should logout user successfully")
        void shouldLogoutUserSuccessfully() {
            // Given
            String token = "valid.jwt.token";
            Date expiration = new Date(System.currentTimeMillis() + 3600000);
            
            when(jwtService.extractExpiration(token)).thenReturn(expiration);
            when(jwtService.extractUserId(token)).thenReturn(testUserId);
            
            // When
            authenticationService.logout(token);
            
            // Then
            verify(valueOperations).set(eq("blacklist_token:" + token), eq(true), anyLong(), eq(TimeUnit.MILLISECONDS));
            verify(redisTemplate).delete("refresh_token:" + testUserId);
        }
    }

    @Nested
    @DisplayName("Password Reset Tests")
    class PasswordResetTests {

        @Test
        @DisplayName("Should initiate password reset for valid email")
        void shouldInitiatePasswordResetForValidEmail() {
            // Given
            String email = "test@example.com";
            
            when(userDetailsService.loadUserByEmail(email)).thenReturn(testUser);
            
            // When
            authenticationService.initiatePasswordReset(email);
            
            // Then
            verify(valueOperations).set(
                startsWith("reset_token:"), 
                eq(testUserId), 
                eq(3600000L), 
                eq(TimeUnit.MILLISECONDS)
            );
        }

        @Test
        @DisplayName("Should handle password reset for non-existent email gracefully")
        void shouldHandlePasswordResetForNonExistentEmailGracefully() {
            // Given
            String email = "nonexistent@example.com";
            
            when(userDetailsService.loadUserByEmail(email)).thenReturn(null);
            
            // When
            authenticationService.initiatePasswordReset(email);
            
            // Then - Should not throw exception and not set any tokens
            verify(valueOperations, never()).set(anyString(), any(), anyLong(), any(TimeUnit.class));
        }

        @Test
        @DisplayName("Should reset password successfully")
        void shouldResetPasswordSuccessfully() {
            // Given
            String resetToken = "valid-reset-token";
            String newPassword = "newPassword123";
            String resetKey = "reset_token:" + resetToken;
            
            when(valueOperations.get(resetKey)).thenReturn(testUserId);
            when(userDetailsService.loadUserById(testUserId)).thenReturn(testUser);
            when(passwordEncoder.encode(newPassword)).thenReturn("$2a$10$hashedNewPassword");
            
            // When
            authenticationService.resetPassword(resetToken, newPassword);
            
            // Then
            verify(userService).save(testUser);
            verify(redisTemplate).delete(resetKey);
            verify(redisTemplate).delete("blacklist_token:user:" + testUserId + ":*");
            assertThat(testUser.getPassword()).isEqualTo("$2a$10$hashedNewPassword");
        }

        @Test
        @DisplayName("Should throw exception for invalid reset token")
        void shouldThrowExceptionForInvalidResetToken() {
            // Given
            String resetToken = "invalid-reset-token";
            String resetKey = "reset_token:" + resetToken;
            
            when(valueOperations.get(resetKey)).thenReturn(null);
            
            // When & Then
            assertThatThrownBy(() -> authenticationService.resetPassword(resetToken, "newPassword"))
                .isInstanceOf(AuthenticationException.class)
                .hasMessage("Invalid or expired reset token");
        }
    }

    @Nested
    @DisplayName("Organization Management Tests")
    class OrganizationManagementTests {

        @Test
        @DisplayName("Should switch organization successfully")
        void shouldSwitchOrganizationSuccessfully() {
            // Given
            String token = "valid.jwt.token";
            String newOrgId = "new-org-id";
            testUser.getOrganizationIds().add(newOrgId);
            
            when(jwtService.extractUserId(token)).thenReturn(testUserId);
            when(userDetailsService.loadUserById(testUserId)).thenReturn(testUser);
            when(jwtService.generateToken(testUser)).thenReturn(testAccessToken);
            when(jwtService.getExpirationTime()).thenReturn(86400000L);
            when(organizationService.getName(newOrgId)).thenReturn("New Org");
            when(organizationService.getUserRole(newOrgId, testUserId)).thenReturn("ADMIN");
            
            // When
            AuthResponse response = authenticationService.switchOrganization(token, newOrgId);
            
            // Then
            assertThat(response).isNotNull();
            assertThat(response.getUser().getCurrentOrganizationId()).isEqualTo(newOrgId);
            assertThat(testUser.getCurrentOrganizationId()).isEqualTo(newOrgId);
            verify(userService).save(testUser);
        }

        @Test
        @DisplayName("Should throw exception when switching to unauthorized organization")
        void shouldThrowExceptionWhenSwitchingToUnauthorizedOrganization() {
            // Given
            String token = "valid.jwt.token";
            String unauthorizedOrgId = "unauthorized-org";
            
            when(jwtService.extractUserId(token)).thenReturn(testUserId);
            when(userDetailsService.loadUserById(testUserId)).thenReturn(testUser);
            
            // When & Then
            assertThatThrownBy(() -> authenticationService.switchOrganization(token, unauthorizedOrgId))
                .isInstanceOf(AuthenticationException.class)
                .hasMessage("User does not belong to the specified organization");
        }

        @Test
        @DisplayName("Should get current user info successfully")
        void shouldGetCurrentUserInfoSuccessfully() {
            // Given
            String token = "valid.jwt.token";
            
            when(jwtService.extractUserId(token)).thenReturn(testUserId);
            when(userDetailsService.loadUserById(testUserId)).thenReturn(testUser);
            when(organizationService.getName(testOrgId)).thenReturn("Test Org");
            when(organizationService.getMemberJoinDate(testOrgId, testUserId)).thenReturn(new Date());
            
            // When
            UserInfoResponse response = authenticationService.getCurrentUser(token);
            
            // Then
            assertThat(response).isNotNull();
            assertThat(response.getId()).isEqualTo(testUserId);
            assertThat(response.getUsername()).isEqualTo("testuser");
            assertThat(response.getEmail()).isEqualTo("test@example.com");
            assertThat(response.getCurrentOrganizationId()).isEqualTo(testOrgId);
        }
    }

    @Nested
    @DisplayName("Edge Cases and Error Handling")
    class EdgeCasesAndErrorHandling {

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {" ", "\t", "\n"})
        @DisplayName("Should handle null and empty usernames gracefully")
        void shouldHandleNullAndEmptyUsernames(String username) {
            // Given
            when(userDetailsService.loadUserByUsername(any())).thenReturn(null);
            when(userDetailsService.loadUserByEmail(any())).thenReturn(null);
            
            // When & Then
            assertThatThrownBy(() -> authenticationService.authenticate(username, "password", null))
                .isInstanceOf(AuthenticationException.class)
                .hasMessage("Invalid credentials");
        }

        @Test
        @DisplayName("Should handle Redis connection failures gracefully")
        void shouldHandleRedisConnectionFailuresGracefully() {
            // Given
            String token = "valid.jwt.token";
            when(redisTemplate.hasKey(anyString())).thenThrow(new RuntimeException("Redis connection failed"));
            
            // When
            TokenValidationResponse response = authenticationService.validateToken(token);
            
            // Then
            assertThat(response.isValid()).isFalse();
            assertThat(response.getError()).contains("Redis connection failed");
        }

        @Test
        @DisplayName("Should handle JWT service exceptions gracefully")
        void shouldHandleJwtServiceExceptionsGracefully() {
            // Given
            String token = "malformed.jwt.token";
            when(redisTemplate.hasKey(anyString())).thenReturn(false);
            when(jwtService.isTokenValid(token)).thenThrow(new RuntimeException("JWT parsing error"));
            
            // When
            TokenValidationResponse response = authenticationService.validateToken(token);
            
            // Then
            assertThat(response.isValid()).isFalse();
            assertThat(response.getError()).contains("JWT parsing error");
        }

        @Test
        @DisplayName("Should handle user service save failures")
        void shouldHandleUserServiceSaveFailures() {
            // Given
            RegisterRequest request = RegisterRequest.builder()
                .username("newuser")
                .email("newuser@example.com")
                .password("password123")
                .build();
            
            when(userDetailsService.loadUserByUsername("newuser")).thenReturn(null);
            when(userDetailsService.loadUserByEmail("newuser@example.com")).thenReturn(null);
            when(passwordEncoder.encode("password123")).thenReturn("$2a$10$hashedPassword");
            when(organizationService.create(anyString(), anyString())).thenReturn("new-org-id");
            doThrow(new RuntimeException("Database save failed")).when(userService).save(any(McpUser.class));
            
            // When & Then
            assertThatThrownBy(() -> authenticationService.register(request))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Database save failed");
        }
    }
}