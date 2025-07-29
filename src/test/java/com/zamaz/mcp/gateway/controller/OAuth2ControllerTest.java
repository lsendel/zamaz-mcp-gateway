package com.zamaz.mcp.gateway.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zamaz.mcp.gateway.service.OAuth2UserPrincipal;
import com.zamaz.mcp.security.audit.SecurityAuditLogger;
import com.zamaz.mcp.security.model.McpUser;
import com.zamaz.mcp.security.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.*;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Comprehensive tests for OAuth2Controller
 */
@WebMvcTest(OAuth2Controller.class)
class OAuth2ControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private ClientRegistrationRepository clientRegistrationRepository;

    @MockBean
    private JwtService jwtService;

    @MockBean
    private SecurityAuditLogger auditLogger;

    private ClientRegistration googleRegistration;
    private ClientRegistration microsoftRegistration;
    private McpUser mockUser;
    private OAuth2UserPrincipal mockOAuth2Principal;

    @BeforeEach
    void setUp() {
        // Setup Google client registration
        googleRegistration = ClientRegistration.withRegistrationId("google")
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

        // Setup Microsoft client registration
        microsoftRegistration = ClientRegistration.withRegistrationId("microsoft")
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

        // Setup mock user
        mockUser = new McpUser();
        mockUser.setId("user-123");
        mockUser.setEmail("john.doe@gmail.com");
        mockUser.setFirstName("John");
        mockUser.setLastName("Doe");
        mockUser.setEmailVerified(true);
        mockUser.setRoles(List.of("ROLE_USER", "OAUTH2_GOOGLE"));
        mockUser.setOrganizationIds(List.of("org-123"));

        // Setup OAuth2 principal
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", "google-user-123");
        attributes.put("email", "john.doe@gmail.com");
        attributes.put("given_name", "John");
        attributes.put("family_name", "Doe");

        mockOAuth2Principal = new OAuth2UserPrincipal(mockUser, attributes);
    }

    @Test
    void getProviders_WithConfiguredProviders_ShouldReturnProviders() throws Exception {
        // Arrange
        when(clientRegistrationRepository.findByRegistrationId("google")).thenReturn(googleRegistration);
        when(clientRegistrationRepository.findByRegistrationId("microsoft")).thenReturn(microsoftRegistration);
        when(clientRegistrationRepository.findByRegistrationId("github")).thenReturn(null);
        when(clientRegistrationRepository.findByRegistrationId("custom")).thenReturn(null);

        // Act & Assert
        mockMvc.perform(get("/api/v1/oauth2/providers"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.providers").isArray())
                .andExpect(jsonPath("$.providers[0].id").value("google"))
                .andExpect(jsonPath("$.providers[0].name").value("Google"))
                .andExpect(jsonPath("$.providers[0].loginUrl").value("http://localhost:8080/oauth2/authorization/google"))
                .andExpect(jsonPath("$.providers[1].id").value("microsoft"))
                .andExpect(jsonPath("$.providers[1].name").value("Microsoft"))
                .andExpect(jsonPath("$.providers[1].loginUrl").value("http://localhost:8080/oauth2/authorization/microsoft"));
    }

    @Test
    void getProviders_WithNoConfiguredProviders_ShouldReturnEmptyList() throws Exception {
        // Arrange
        when(clientRegistrationRepository.findByRegistrationId(anyString())).thenReturn(null);

        // Act & Assert
        mockMvc.perform(get("/api/v1/oauth2/providers"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.providers").isEmpty());
    }

    @Test
    void getCurrentUser_WithOAuth2Authentication_ShouldReturnUserInfo() throws Exception {
        // Arrange
        when(jwtService.generateToken(anyString())).thenReturn("mock-jwt-token");

        // Act & Assert
        mockMvc.perform(get("/api/v1/oauth2/user")
                        .with(request -> {
                            request.setUserPrincipal(mockOAuth2Principal);
                            return request;
                        }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("user-123"))
                .andExpect(jsonPath("$.email").value("john.doe@gmail.com"))
                .andExpect(jsonPath("$.firstName").value("John"))
                .andExpect(jsonPath("$.lastName").value("Doe"))
                .andExpect(jsonPath("$.emailVerified").value(true))
                .andExpect(jsonPath("$.provider").value("google"))
                .andExpect(jsonPath("$.roles").isArray())
                .andExpect(jsonPath("$.organizations").isArray());
    }

    @Test
    void getCurrentUser_WithNoAuthentication_ShouldReturn401() throws Exception {
        // Act & Assert
        mockMvc.perform(get("/api/v1/oauth2/user"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "user-123")
    void getCurrentUser_WithJWTAuthentication_ShouldReturnBasicUserInfo() throws Exception {
        // Act & Assert
        mockMvc.perform(get("/api/v1/oauth2/user")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("user-123"))
                .andExpect(jsonPath("$.email").value("user-123"))
                .andExpect(jsonPath("$.provider").value("jwt"));
    }

    @Test
    @WithMockUser(username = "user-123")
    void linkAccount_WithValidProvider_ShouldReturnLinkUrl() throws Exception {
        // Act & Assert
        mockMvc.perform(post("/api/v1/oauth2/link")
                        .with(csrf())
                        .param("provider", "google"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Account linking initiated"))
                .andExpect(jsonPath("$.linkUrl").value("http://localhost:8080/oauth2/authorization/google?link=true"));

        verify(auditLogger).logSecurityEvent(
            eq(SecurityAuditLogger.SecurityEventType.OAUTH2_ACCOUNT_LINKED),
            eq(SecurityAuditLogger.RiskLevel.MEDIUM),
            anyString(),
            anyMap()
        );
    }

    @Test
    void linkAccount_WithoutAuthentication_ShouldReturn401() throws Exception {
        // Act & Assert
        mockMvc.perform(post("/api/v1/oauth2/link")
                        .with(csrf())
                        .param("provider", "google"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "user-123")
    void unlinkAccount_WithValidProvider_ShouldReturnSuccess() throws Exception {
        // Act & Assert
        mockMvc.perform(delete("/api/v1/oauth2/unlink")
                        .with(csrf())
                        .param("provider", "google"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Account unlinked successfully"));

        verify(auditLogger).logSecurityEvent(
            eq(SecurityAuditLogger.SecurityEventType.OAUTH2_ACCOUNT_UNLINKED),
            eq(SecurityAuditLogger.RiskLevel.MEDIUM),
            anyString(),
            anyMap()
        );
    }

    @Test
    void unlinkAccount_WithoutAuthentication_ShouldReturn401() throws Exception {
        // Act & Assert
        mockMvc.perform(delete("/api/v1/oauth2/unlink")
                        .with(csrf())
                        .param("provider", "google"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void handleCallback_WithSuccessfulAuthentication_ShouldReturnToken() throws Exception {
        // Arrange
        when(jwtService.generateToken(anyString())).thenReturn("mock-jwt-token");

        // Act & Assert
        mockMvc.perform(get("/api/v1/oauth2/callback")
                        .param("code", "auth-code-123")
                        .param("state", "state-456")
                        .with(request -> {
                            request.setUserPrincipal(mockOAuth2Principal);
                            return request;
                        }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("mock-jwt-token"))
                .andExpect(jsonPath("$.message").value("Authentication successful"));
    }

    @Test
    void handleCallback_WithError_ShouldReturnError() throws Exception {
        // Act & Assert
        mockMvc.perform(get("/api/v1/oauth2/callback")
                        .param("error", "access_denied")
                        .param("error_description", "User denied access"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("access_denied"));
    }

    @Test
    void handleCallback_WithoutAuthentication_ShouldReturnError() throws Exception {
        // Act & Assert
        mockMvc.perform(get("/api/v1/oauth2/callback")
                        .param("code", "auth-code-123")
                        .param("state", "state-456"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Authentication failed"));
    }

    @Test
    void getProviders_WithAllProviders_ShouldReturnAllConfiguredProviders() throws Exception {
        // Arrange
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
            .clientName("Custom OIDC")
            .build();

        when(clientRegistrationRepository.findByRegistrationId("google")).thenReturn(googleRegistration);
        when(clientRegistrationRepository.findByRegistrationId("microsoft")).thenReturn(microsoftRegistration);
        when(clientRegistrationRepository.findByRegistrationId("github")).thenReturn(githubRegistration);
        when(clientRegistrationRepository.findByRegistrationId("custom")).thenReturn(customRegistration);

        // Act & Assert
        mockMvc.perform(get("/api/v1/oauth2/providers"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.providers").isArray())
                .andExpect(jsonPath("$.providers").isNotEmpty())
                .andExpect(jsonPath("$.providers[?(@.id=='google')].name").value("Google"))
                .andExpect(jsonPath("$.providers[?(@.id=='microsoft')].name").value("Microsoft"))
                .andExpect(jsonPath("$.providers[?(@.id=='github')].name").value("GitHub"))
                .andExpect(jsonPath("$.providers[?(@.id=='custom')].name").value("Custom OIDC"));
    }

    @Test
    void getCurrentUser_WithComplexUserRoles_ShouldReturnAllRoles() throws Exception {
        // Arrange
        mockUser.setRoles(List.of("ROLE_USER", "ROLE_ADMIN", "OAUTH2_GOOGLE", "OAUTH2_MICROSOFT"));
        mockUser.setOrganizationIds(List.of("org-123", "org-456"));

        // Act & Assert
        mockMvc.perform(get("/api/v1/oauth2/user")
                        .with(request -> {
                            request.setUserPrincipal(mockOAuth2Principal);
                            return request;
                        }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("user-123"))
                .andExpect(jsonPath("$.roles").isArray())
                .andExpect(jsonPath("$.roles.length()").value(4))
                .andExpect(jsonPath("$.organizations").isArray())
                .andExpect(jsonPath("$.organizations.length()").value(2));
    }

    @Test
    @WithMockUser(username = "user-123")
    void linkAccount_WithMultipleProviders_ShouldHandleEachProvider() throws Exception {
        // Test linking with different providers
        String[] providers = {"google", "microsoft", "github", "custom"};
        
        for (String provider : providers) {
            mockMvc.perform(post("/api/v1/oauth2/link")
                            .with(csrf())
                            .param("provider", provider))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Account linking initiated"))
                    .andExpect(jsonPath("$.linkUrl").value("http://localhost:8080/oauth2/authorization/" + provider + "?link=true"));
        }

        // Verify audit logging for each provider
        verify(auditLogger, times(4)).logSecurityEvent(
            eq(SecurityAuditLogger.SecurityEventType.OAUTH2_ACCOUNT_LINKED),
            eq(SecurityAuditLogger.RiskLevel.MEDIUM),
            anyString(),
            anyMap()
        );
    }

    @Test
    @WithMockUser(username = "user-123")
    void unlinkAccount_WithMultipleProviders_ShouldHandleEachProvider() throws Exception {
        // Test unlinking with different providers
        String[] providers = {"google", "microsoft", "github", "custom"};
        
        for (String provider : providers) {
            mockMvc.perform(delete("/api/v1/oauth2/unlink")
                            .with(csrf())
                            .param("provider", provider))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Account unlinked successfully"));
        }

        // Verify audit logging for each provider
        verify(auditLogger, times(4)).logSecurityEvent(
            eq(SecurityAuditLogger.SecurityEventType.OAUTH2_ACCOUNT_UNLINKED),
            eq(SecurityAuditLogger.RiskLevel.MEDIUM),
            anyString(),
            anyMap()
        );
    }

    @Test
    void handleCallback_WithDifferentErrorTypes_ShouldHandleAllErrors() throws Exception {
        // Test different OAuth2 error types
        String[] errors = {"access_denied", "invalid_request", "invalid_client", "server_error"};
        
        for (String error : errors) {
            mockMvc.perform(get("/api/v1/oauth2/callback")
                            .param("error", error))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value(error));
        }
    }

    @Test
    void getCurrentUser_WithUnverifiedEmail_ShouldReturnUnverifiedStatus() throws Exception {
        // Arrange
        mockUser.setEmailVerified(false);

        // Act & Assert
        mockMvc.perform(get("/api/v1/oauth2/user")
                        .with(request -> {
                            request.setUserPrincipal(mockOAuth2Principal);
                            return request;
                        }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("user-123"))
                .andExpect(jsonPath("$.emailVerified").value(false));
    }
}