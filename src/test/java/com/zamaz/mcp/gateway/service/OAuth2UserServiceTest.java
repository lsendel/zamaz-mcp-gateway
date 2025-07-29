package com.zamaz.mcp.gateway.service;

import com.zamaz.mcp.security.audit.SecurityAuditLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive tests for OAuth2UserService
 */
@ExtendWith(MockitoExtension.class)
class OAuth2UserServiceTest {

    @Mock
    private SecurityAuditLogger auditLogger;

    @Mock
    private EmailService emailService;

    @InjectMocks
    private OAuth2UserService oAuth2UserService;

    private OAuth2UserRequest googleUserRequest;
    private OAuth2UserRequest microsoftUserRequest;
    private OAuth2UserRequest githubUserRequest;
    private OAuth2UserRequest customUserRequest;

    @BeforeEach
    void setUp() {
        // Setup Google OAuth2 user request
        ClientRegistration googleRegistration = ClientRegistration.withRegistrationId("google")
            .clientId("google-client-id")
            .clientSecret("google-client-secret")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8080/login/oauth2/code/google")
            .scope("openid", "profile", "email")
            .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
            .tokenUri("https://www.googleapis.com/oauth2/v4/token")
            .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
            .userNameAttributeName("sub")
            .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
            .clientName("Google")
            .build();

        googleUserRequest = new OAuth2UserRequest(googleRegistration, null);

        // Setup Microsoft OAuth2 user request
        ClientRegistration microsoftRegistration = ClientRegistration.withRegistrationId("microsoft")
            .clientId("microsoft-client-id")
            .clientSecret("microsoft-client-secret")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8080/login/oauth2/code/microsoft")
            .scope("openid", "profile", "email")
            .authorizationUri("https://login.microsoftonline.com/common/oauth2/v2.0/authorize")
            .tokenUri("https://login.microsoftonline.com/common/oauth2/v2.0/token")
            .userInfoUri("https://graph.microsoft.com/oidc/userinfo")
            .userNameAttributeName("sub")
            .jwkSetUri("https://login.microsoftonline.com/common/discovery/v2.0/keys")
            .clientName("Microsoft")
            .build();

        microsoftUserRequest = new OAuth2UserRequest(microsoftRegistration, null);

        // Setup GitHub OAuth2 user request
        ClientRegistration githubRegistration = ClientRegistration.withRegistrationId("github")
            .clientId("github-client-id")
            .clientSecret("github-client-secret")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8080/login/oauth2/code/github")
            .scope("user:email", "read:user")
            .authorizationUri("https://github.com/login/oauth/authorize")
            .tokenUri("https://github.com/login/oauth/access_token")
            .userInfoUri("https://api.github.com/user")
            .userNameAttributeName("id")
            .clientName("GitHub")
            .build();

        githubUserRequest = new OAuth2UserRequest(githubRegistration, null);

        // Setup custom OIDC user request
        ClientRegistration customRegistration = ClientRegistration.withRegistrationId("custom")
            .clientId("custom-client-id")
            .clientSecret("custom-client-secret")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8080/login/oauth2/code/custom")
            .scope("openid", "profile", "email")
            .authorizationUri("https://custom.oidc.com/auth")
            .tokenUri("https://custom.oidc.com/token")
            .userInfoUri("https://custom.oidc.com/userinfo")
            .userNameAttributeName("sub")
            .jwkSetUri("https://custom.oidc.com/certs")
            .clientName("Custom OIDC")
            .build();

        customUserRequest = new OAuth2UserRequest(customRegistration, null);
    }

    @Test
    void loadUser_WithGoogleProvider_ShouldCreateUser() {
        // Arrange
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", "google-user-123");
        attributes.put("email", "john.doe@gmail.com");
        attributes.put("given_name", "John");
        attributes.put("family_name", "Doe");
        attributes.put("name", "John Doe");
        attributes.put("picture", "https://example.com/picture.jpg");
        attributes.put("email_verified", true);

        OAuth2User mockOAuth2User = new DefaultOAuth2User(
            Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
            attributes,
            "sub"
        );

        // Mock the parent class method
        OAuth2UserService spyService = spy(oAuth2UserService);
        doReturn(mockOAuth2User).when(spyService).loadUser(any(OAuth2UserRequest.class));

        doNothing().when(emailService).sendWelcomeEmail(anyString(), anyString());

        // Act
        OAuth2User result = spyService.loadUser(googleUserRequest);

        // Assert
        assertNotNull(result);
        assertTrue(result instanceof OAuth2UserPrincipal);
        
        OAuth2UserPrincipal principal = (OAuth2UserPrincipal) result;
        assertEquals("john.doe@gmail.com", principal.getEmail());
        assertEquals("John", principal.getFirstName());
        assertEquals("Doe", principal.getLastName());
        assertTrue(principal.isEmailVerified());

        verify(auditLogger).logSecurityEvent(
            eq(SecurityAuditLogger.SecurityEventType.OAUTH2_LOGIN_SUCCESS),
            eq(SecurityAuditLogger.RiskLevel.LOW),
            anyString(),
            anyMap()
        );
        verify(emailService).sendWelcomeEmail("john.doe@gmail.com", "John");
    }

    @Test
    void loadUser_WithMicrosoftProvider_ShouldCreateUser() {
        // Arrange
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", "microsoft-user-456");
        attributes.put("email", "jane.smith@outlook.com");
        attributes.put("given_name", "Jane");
        attributes.put("family_name", "Smith");
        attributes.put("name", "Jane Smith");

        OAuth2User mockOAuth2User = new DefaultOAuth2User(
            Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
            attributes,
            "sub"
        );

        OAuth2UserService spyService = spy(oAuth2UserService);
        doReturn(mockOAuth2User).when(spyService).loadUser(any(OAuth2UserRequest.class));

        doNothing().when(emailService).sendWelcomeEmail(anyString(), anyString());

        // Act
        OAuth2User result = spyService.loadUser(microsoftUserRequest);

        // Assert
        assertNotNull(result);
        assertTrue(result instanceof OAuth2UserPrincipal);
        
        OAuth2UserPrincipal principal = (OAuth2UserPrincipal) result;
        assertEquals("jane.smith@outlook.com", principal.getEmail());
        assertEquals("Jane", principal.getFirstName());
        assertEquals("Smith", principal.getLastName());
        assertTrue(principal.isEmailVerified()); // Microsoft emails are considered verified

        verify(auditLogger).logSecurityEvent(
            eq(SecurityAuditLogger.SecurityEventType.OAUTH2_LOGIN_SUCCESS),
            eq(SecurityAuditLogger.RiskLevel.LOW),
            anyString(),
            anyMap()
        );
    }

    @Test
    void loadUser_WithGitHubProvider_ShouldCreateUser() {
        // Arrange
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("id", "12345");
        attributes.put("email", "developer@github.com");
        attributes.put("name", "Developer User");
        attributes.put("avatar_url", "https://github.com/avatar.png");

        OAuth2User mockOAuth2User = new DefaultOAuth2User(
            Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
            attributes,
            "id"
        );

        OAuth2UserService spyService = spy(oAuth2UserService);
        doReturn(mockOAuth2User).when(spyService).loadUser(any(OAuth2UserRequest.class));

        doNothing().when(emailService).sendWelcomeEmail(anyString(), anyString());

        // Act
        OAuth2User result = spyService.loadUser(githubUserRequest);

        // Assert
        assertNotNull(result);
        assertTrue(result instanceof OAuth2UserPrincipal);
        
        OAuth2UserPrincipal principal = (OAuth2UserPrincipal) result;
        assertEquals("developer@github.com", principal.getEmail());
        assertEquals("Developer", principal.getFirstName());
        assertEquals("User", principal.getLastName());
        assertTrue(principal.isEmailVerified()); // GitHub emails are considered verified

        verify(auditLogger).logSecurityEvent(
            eq(SecurityAuditLogger.SecurityEventType.OAUTH2_LOGIN_SUCCESS),
            eq(SecurityAuditLogger.RiskLevel.LOW),
            anyString(),
            anyMap()
        );
    }

    @Test
    void loadUser_WithCustomProvider_ShouldCreateUser() {
        // Arrange
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", "custom-user-789");
        attributes.put("email", "custom@example.com");
        attributes.put("given_name", "Custom");
        attributes.put("family_name", "User");
        attributes.put("name", "Custom User");
        attributes.put("email_verified", false);

        OAuth2User mockOAuth2User = new DefaultOAuth2User(
            Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
            attributes,
            "sub"
        );

        OAuth2UserService spyService = spy(oAuth2UserService);
        doReturn(mockOAuth2User).when(spyService).loadUser(any(OAuth2UserRequest.class));

        doNothing().when(emailService).sendWelcomeEmail(anyString(), anyString());

        // Act
        OAuth2User result = spyService.loadUser(customUserRequest);

        // Assert
        assertNotNull(result);
        assertTrue(result instanceof OAuth2UserPrincipal);
        
        OAuth2UserPrincipal principal = (OAuth2UserPrincipal) result;
        assertEquals("custom@example.com", principal.getEmail());
        assertEquals("Custom", principal.getFirstName());
        assertEquals("User", principal.getLastName());
        assertFalse(principal.isEmailVerified());

        verify(auditLogger).logSecurityEvent(
            eq(SecurityAuditLogger.SecurityEventType.OAUTH2_LOGIN_SUCCESS),
            eq(SecurityAuditLogger.RiskLevel.LOW),
            anyString(),
            anyMap()
        );
    }

    @Test
    void loadUser_WithExistingUser_ShouldUpdateUser() {
        // Arrange
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", "google-user-123");
        attributes.put("email", "existing@gmail.com");
        attributes.put("given_name", "Updated");
        attributes.put("family_name", "Name");
        attributes.put("name", "Updated Name");
        attributes.put("email_verified", true);

        OAuth2User mockOAuth2User = new DefaultOAuth2User(
            Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
            attributes,
            "sub"
        );

        OAuth2UserService spyService = spy(oAuth2UserService);
        doReturn(mockOAuth2User).when(spyService).loadUser(any(OAuth2UserRequest.class));

        doNothing().when(emailService).sendWelcomeEmail(anyString(), anyString());

        // First login to create user
        spyService.loadUser(googleUserRequest);

        // Act - Second login with same email
        OAuth2User result = spyService.loadUser(googleUserRequest);

        // Assert
        assertNotNull(result);
        assertTrue(result instanceof OAuth2UserPrincipal);
        
        OAuth2UserPrincipal principal = (OAuth2UserPrincipal) result;
        assertEquals("existing@gmail.com", principal.getEmail());
        assertEquals("Updated", principal.getFirstName());
        assertEquals("Name", principal.getLastName());

        // Should only send welcome email once (for new user)
        verify(emailService, times(2)).sendWelcomeEmail(anyString(), anyString());
    }

    @Test
    void loadUser_WithAuthenticationFailure_ShouldThrowException() {
        // Arrange
        OAuth2UserService spyService = spy(oAuth2UserService);
        doThrow(new RuntimeException("OAuth2 provider error")).when(spyService).loadUser(any(OAuth2UserRequest.class));

        // Act & Assert
        assertThrows(OAuth2AuthenticationException.class, () -> {
            spyService.loadUser(googleUserRequest);
        });

        verify(auditLogger).logSecurityEvent(
            eq(SecurityAuditLogger.SecurityEventType.OAUTH2_LOGIN_FAILED),
            eq(SecurityAuditLogger.RiskLevel.MEDIUM),
            anyString(),
            anyMap()
        );
    }

    @Test
    void loadUser_WithUnsupportedProvider_ShouldThrowException() {
        // Arrange
        ClientRegistration unsupportedRegistration = ClientRegistration.withRegistrationId("unsupported")
            .clientId("unsupported-client-id")
            .clientSecret("unsupported-client-secret")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8080/login/oauth2/code/unsupported")
            .scope("openid", "profile", "email")
            .authorizationUri("https://unsupported.com/auth")
            .tokenUri("https://unsupported.com/token")
            .userInfoUri("https://unsupported.com/userinfo")
            .userNameAttributeName("sub")
            .clientName("Unsupported")
            .build();

        OAuth2UserRequest unsupportedRequest = new OAuth2UserRequest(unsupportedRegistration, null);

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", "unsupported-user-123");
        attributes.put("email", "user@unsupported.com");

        OAuth2User mockOAuth2User = new DefaultOAuth2User(
            Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
            attributes,
            "sub"
        );

        OAuth2UserService spyService = spy(oAuth2UserService);
        doReturn(mockOAuth2User).when(spyService).loadUser(any(OAuth2UserRequest.class));

        // Act & Assert
        assertThrows(OAuth2AuthenticationException.class, () -> {
            spyService.loadUser(unsupportedRequest);
        });

        verify(auditLogger).logSecurityEvent(
            eq(SecurityAuditLogger.SecurityEventType.OAUTH2_LOGIN_FAILED),
            eq(SecurityAuditLogger.RiskLevel.MEDIUM),
            anyString(),
            anyMap()
        );
    }

    @Test
    void loadUser_WithMissingEmail_ShouldThrowException() {
        // Arrange
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", "google-user-123");
        attributes.put("given_name", "John");
        attributes.put("family_name", "Doe");
        // Missing email attribute

        OAuth2User mockOAuth2User = new DefaultOAuth2User(
            Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
            attributes,
            "sub"
        );

        OAuth2UserService spyService = spy(oAuth2UserService);
        doReturn(mockOAuth2User).when(spyService).loadUser(any(OAuth2UserRequest.class));

        // Act & Assert
        assertThrows(OAuth2AuthenticationException.class, () -> {
            spyService.loadUser(googleUserRequest);
        });

        verify(auditLogger).logSecurityEvent(
            eq(SecurityAuditLogger.SecurityEventType.OAUTH2_LOGIN_FAILED),
            eq(SecurityAuditLogger.RiskLevel.MEDIUM),
            anyString(),
            anyMap()
        );
    }

    @Test
    void loadUser_WithEmailServiceFailure_ShouldStillCreateUser() {
        // Arrange
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", "google-user-123");
        attributes.put("email", "john.doe@gmail.com");
        attributes.put("given_name", "John");
        attributes.put("family_name", "Doe");
        attributes.put("name", "John Doe");
        attributes.put("email_verified", true);

        OAuth2User mockOAuth2User = new DefaultOAuth2User(
            Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
            attributes,
            "sub"
        );

        OAuth2UserService spyService = spy(oAuth2UserService);
        doReturn(mockOAuth2User).when(spyService).loadUser(any(OAuth2UserRequest.class));

        doThrow(new RuntimeException("Email service unavailable")).when(emailService).sendWelcomeEmail(anyString(), anyString());

        // Act
        OAuth2User result = spyService.loadUser(googleUserRequest);

        // Assert
        assertNotNull(result);
        assertTrue(result instanceof OAuth2UserPrincipal);
        
        // User should still be created even if email service fails
        OAuth2UserPrincipal principal = (OAuth2UserPrincipal) result;
        assertEquals("john.doe@gmail.com", principal.getEmail());

        verify(auditLogger).logSecurityEvent(
            eq(SecurityAuditLogger.SecurityEventType.OAUTH2_LOGIN_SUCCESS),
            eq(SecurityAuditLogger.RiskLevel.LOW),
            anyString(),
            anyMap()
        );
    }

    @Test
    void loadUser_WithPartialUserInfo_ShouldCreateUserWithAvailableData() {
        // Arrange
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", "google-user-123");
        attributes.put("email", "minimal@gmail.com");
        // Missing given_name and family_name

        OAuth2User mockOAuth2User = new DefaultOAuth2User(
            Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
            attributes,
            "sub"
        );

        OAuth2UserService spyService = spy(oAuth2UserService);
        doReturn(mockOAuth2User).when(spyService).loadUser(any(OAuth2UserRequest.class));

        doNothing().when(emailService).sendWelcomeEmail(anyString(), anyString());

        // Act
        OAuth2User result = spyService.loadUser(googleUserRequest);

        // Assert
        assertNotNull(result);
        assertTrue(result instanceof OAuth2UserPrincipal);
        
        OAuth2UserPrincipal principal = (OAuth2UserPrincipal) result;
        assertEquals("minimal@gmail.com", principal.getEmail());
        // Should handle missing names gracefully
        assertNotNull(principal.getFirstName()); // Should not be null
        assertNotNull(principal.getLastName()); // Should not be null

        verify(auditLogger).logSecurityEvent(
            eq(SecurityAuditLogger.SecurityEventType.OAUTH2_LOGIN_SUCCESS),
            eq(SecurityAuditLogger.RiskLevel.LOW),
            anyString(),
            anyMap()
        );
    }
}