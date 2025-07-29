package com.zamaz.mcp.gateway.config;

import com.zamaz.mcp.gateway.service.OAuth2UserService;
import com.zamaz.mcp.security.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for OAuth2Config
 */
@ExtendWith(MockitoExtension.class)
@SpringBootTest
@TestPropertySource(properties = {
    "oauth2.google.client-id=test-google-client-id",
    "oauth2.google.client-secret=test-google-client-secret",
    "oauth2.microsoft.client-id=test-microsoft-client-id",
    "oauth2.microsoft.client-secret=test-microsoft-client-secret",
    "oauth2.github.client-id=test-github-client-id",
    "oauth2.github.client-secret=test-github-client-secret",
    "oauth2.custom.client-id=test-custom-client-id",
    "oauth2.custom.client-secret=test-custom-client-secret",
    "oauth2.custom.issuer-uri=https://custom.oidc.com",
    "oauth2.custom.jwk-set-uri=https://custom.oidc.com/certs",
    "oauth2.redirect-uri=http://localhost:8080/login/oauth2/code/",
    "oauth2.success-redirect-uri=http://localhost:3000/dashboard",
    "oauth2.failure-redirect-uri=http://localhost:3000/login?error=oauth2",
    "jwt.secret=test-jwt-secret-key-for-testing"
})
class OAuth2ConfigTest {

    @Mock
    private OAuth2UserService oAuth2UserService;

    @Mock
    private JwtService jwtService;

    private OAuth2Config oauth2Config;

    @BeforeEach
    void setUp() {
        oauth2Config = new OAuth2Config(oAuth2UserService, jwtService);
        
        // Set test properties via reflection
        ReflectionTestUtils.setField(oauth2Config, "googleClientId", "test-google-client-id");
        ReflectionTestUtils.setField(oauth2Config, "googleClientSecret", "test-google-client-secret");
        ReflectionTestUtils.setField(oauth2Config, "microsoftClientId", "test-microsoft-client-id");
        ReflectionTestUtils.setField(oauth2Config, "microsoftClientSecret", "test-microsoft-client-secret");
        ReflectionTestUtils.setField(oauth2Config, "githubClientId", "test-github-client-id");
        ReflectionTestUtils.setField(oauth2Config, "githubClientSecret", "test-github-client-secret");
        ReflectionTestUtils.setField(oauth2Config, "customClientId", "test-custom-client-id");
        ReflectionTestUtils.setField(oauth2Config, "customClientSecret", "test-custom-client-secret");
        ReflectionTestUtils.setField(oauth2Config, "customIssuerUri", "https://custom.oidc.com");
        ReflectionTestUtils.setField(oauth2Config, "customJwkSetUri", "https://custom.oidc.com/certs");
        ReflectionTestUtils.setField(oauth2Config, "redirectUri", "http://localhost:8080/login/oauth2/code/");
        ReflectionTestUtils.setField(oauth2Config, "successRedirectUri", "http://localhost:3000/dashboard");
        ReflectionTestUtils.setField(oauth2Config, "failureRedirectUri", "http://localhost:3000/login?error=oauth2");
        ReflectionTestUtils.setField(oauth2Config, "jwtSecret", "test-jwt-secret-key-for-testing");
    }

    @Test
    void clientRegistrationRepository_WithAllProvidersConfigured_ShouldReturnAllRegistrations() {
        // Act
        ClientRegistrationRepository repository = oauth2Config.clientRegistrationRepository();

        // Assert
        assertNotNull(repository);
        
        // Test Google registration
        ClientRegistration googleRegistration = repository.findByRegistrationId("google");
        assertNotNull(googleRegistration);
        assertEquals("google", googleRegistration.getRegistrationId());
        assertEquals("test-google-client-id", googleRegistration.getClientId());
        assertEquals("test-google-client-secret", googleRegistration.getClientSecret());
        assertEquals("Google", googleRegistration.getClientName());
        assertTrue(googleRegistration.getScopes().contains("openid"));
        assertTrue(googleRegistration.getScopes().contains("profile"));
        assertTrue(googleRegistration.getScopes().contains("email"));

        // Test Microsoft registration
        ClientRegistration microsoftRegistration = repository.findByRegistrationId("microsoft");
        assertNotNull(microsoftRegistration);
        assertEquals("microsoft", microsoftRegistration.getRegistrationId());
        assertEquals("test-microsoft-client-id", microsoftRegistration.getClientId());
        assertEquals("test-microsoft-client-secret", microsoftRegistration.getClientSecret());
        assertEquals("Microsoft", microsoftRegistration.getClientName());

        // Test GitHub registration
        ClientRegistration githubRegistration = repository.findByRegistrationId("github");
        assertNotNull(githubRegistration);
        assertEquals("github", githubRegistration.getRegistrationId());
        assertEquals("test-github-client-id", githubRegistration.getClientId());
        assertEquals("test-github-client-secret", githubRegistration.getClientSecret());
        assertEquals("GitHub", githubRegistration.getClientName());
        assertTrue(githubRegistration.getScopes().contains("user:email"));
        assertTrue(githubRegistration.getScopes().contains("read:user"));

        // Test Custom registration
        ClientRegistration customRegistration = repository.findByRegistrationId("custom");
        assertNotNull(customRegistration);
        assertEquals("custom", customRegistration.getRegistrationId());
        assertEquals("test-custom-client-id", customRegistration.getClientId());
        assertEquals("test-custom-client-secret", customRegistration.getClientSecret());
        assertEquals("Custom OIDC", customRegistration.getClientName());
        assertEquals("https://custom.oidc.com/auth", customRegistration.getProviderDetails().getAuthorizationUri());
        assertEquals("https://custom.oidc.com/token", customRegistration.getProviderDetails().getTokenUri());
        assertEquals("https://custom.oidc.com/userinfo", customRegistration.getProviderDetails().getUserInfoEndpoint().getUri());
        assertEquals("https://custom.oidc.com/certs", customRegistration.getProviderDetails().getJwkSetUri());
    }

    @Test
    void clientRegistrationRepository_WithNoProvidersConfigured_ShouldReturnEmptyRepository() {
        // Arrange
        OAuth2Config emptyConfig = new OAuth2Config(oAuth2UserService, jwtService);
        // Don't set any client IDs or secrets

        // Act
        ClientRegistrationRepository repository = emptyConfig.clientRegistrationRepository();

        // Assert
        assertNotNull(repository);
        assertNull(repository.findByRegistrationId("google"));
        assertNull(repository.findByRegistrationId("microsoft"));
        assertNull(repository.findByRegistrationId("github"));
        assertNull(repository.findByRegistrationId("custom"));
    }

    @Test
    void clientRegistrationRepository_WithPartialConfiguration_ShouldReturnOnlyConfiguredProviders() {
        // Arrange
        OAuth2Config partialConfig = new OAuth2Config(oAuth2UserService, jwtService);
        ReflectionTestUtils.setField(partialConfig, "googleClientId", "test-google-client-id");
        ReflectionTestUtils.setField(partialConfig, "googleClientSecret", "test-google-client-secret");
        ReflectionTestUtils.setField(partialConfig, "redirectUri", "http://localhost:8080/login/oauth2/code/");
        // Don't configure other providers

        // Act
        ClientRegistrationRepository repository = partialConfig.clientRegistrationRepository();

        // Assert
        assertNotNull(repository);
        assertNotNull(repository.findByRegistrationId("google"));
        assertNull(repository.findByRegistrationId("microsoft"));
        assertNull(repository.findByRegistrationId("github"));
        assertNull(repository.findByRegistrationId("custom"));
    }

    @Test
    void jwtDecoder_ShouldReturnValidDecoder() {
        // Act
        JwtDecoder decoder = oauth2Config.jwtDecoder();

        // Assert
        assertNotNull(decoder);
        // JWT decoder should be properly configured with the secret
    }

    @Test
    void oauth2SuccessHandler_ShouldReturnValidHandler() {
        // Arrange
        when(jwtService.generateToken(anyString())).thenReturn("test-jwt-token");

        // Act
        AuthenticationSuccessHandler handler = oauth2Config.oauth2SuccessHandler();

        // Assert
        assertNotNull(handler);
        // Handler should be properly configured
    }

    @Test
    void oauth2FailureHandler_ShouldReturnValidHandler() {
        // Act
        AuthenticationFailureHandler handler = oauth2Config.oauth2FailureHandler();

        // Assert
        assertNotNull(handler);
        // Handler should be properly configured
    }

    @Test
    void clientRegistrationRepository_WithCustomProviderWithoutJwkSetUri_ShouldUseDefaultJwkSetUri() {
        // Arrange
        OAuth2Config configWithoutJwkSet = new OAuth2Config(oAuth2UserService, jwtService);
        ReflectionTestUtils.setField(configWithoutJwkSet, "customClientId", "test-custom-client-id");
        ReflectionTestUtils.setField(configWithoutJwkSet, "customClientSecret", "test-custom-client-secret");
        ReflectionTestUtils.setField(configWithoutJwkSet, "customIssuerUri", "https://custom.oidc.com");
        ReflectionTestUtils.setField(configWithoutJwkSet, "customJwkSetUri", null);
        ReflectionTestUtils.setField(configWithoutJwkSet, "redirectUri", "http://localhost:8080/login/oauth2/code/");

        // Act
        ClientRegistrationRepository repository = configWithoutJwkSet.clientRegistrationRepository();

        // Assert
        ClientRegistration customRegistration = repository.findByRegistrationId("custom");
        assertNotNull(customRegistration);
        assertEquals("https://custom.oidc.com/certs", customRegistration.getProviderDetails().getJwkSetUri());
    }

    @Test
    void clientRegistrationRepository_WithEmptyClientCredentials_ShouldNotIncludeProvider() {
        // Arrange
        OAuth2Config configWithEmptyCredentials = new OAuth2Config(oAuth2UserService, jwtService);
        ReflectionTestUtils.setField(configWithEmptyCredentials, "googleClientId", "");
        ReflectionTestUtils.setField(configWithEmptyCredentials, "googleClientSecret", "");
        ReflectionTestUtils.setField(configWithEmptyCredentials, "redirectUri", "http://localhost:8080/login/oauth2/code/");

        // Act
        ClientRegistrationRepository repository = configWithEmptyCredentials.clientRegistrationRepository();

        // Assert
        assertNull(repository.findByRegistrationId("google"));
    }

    @Test
    void clientRegistrationRepository_WithWhitespaceCredentials_ShouldNotIncludeProvider() {
        // Arrange
        OAuth2Config configWithWhitespaceCredentials = new OAuth2Config(oAuth2UserService, jwtService);
        ReflectionTestUtils.setField(configWithWhitespaceCredentials, "googleClientId", "   ");
        ReflectionTestUtils.setField(configWithWhitespaceCredentials, "googleClientSecret", "   ");
        ReflectionTestUtils.setField(configWithWhitespaceCredentials, "redirectUri", "http://localhost:8080/login/oauth2/code/");

        // Act
        ClientRegistrationRepository repository = configWithWhitespaceCredentials.clientRegistrationRepository();

        // Assert
        assertNull(repository.findByRegistrationId("google"));
    }

    @Test
    void clientRegistrationRepository_WithMissingClientSecret_ShouldNotIncludeProvider() {
        // Arrange
        OAuth2Config configWithMissingSecret = new OAuth2Config(oAuth2UserService, jwtService);
        ReflectionTestUtils.setField(configWithMissingSecret, "googleClientId", "test-google-client-id");
        ReflectionTestUtils.setField(configWithMissingSecret, "googleClientSecret", null);
        ReflectionTestUtils.setField(configWithMissingSecret, "redirectUri", "http://localhost:8080/login/oauth2/code/");

        // Act
        ClientRegistrationRepository repository = configWithMissingSecret.clientRegistrationRepository();

        // Assert
        assertNull(repository.findByRegistrationId("google"));
    }

    @Test
    void clientRegistrationRepository_WithMissingClientId_ShouldNotIncludeProvider() {
        // Arrange
        OAuth2Config configWithMissingId = new OAuth2Config(oAuth2UserService, jwtService);
        ReflectionTestUtils.setField(configWithMissingId, "googleClientId", null);
        ReflectionTestUtils.setField(configWithMissingId, "googleClientSecret", "test-google-client-secret");
        ReflectionTestUtils.setField(configWithMissingId, "redirectUri", "http://localhost:8080/login/oauth2/code/");

        // Act
        ClientRegistrationRepository repository = configWithMissingId.clientRegistrationRepository();

        // Assert
        assertNull(repository.findByRegistrationId("google"));
    }

    @Test
    void clientRegistrationRepository_WithCustomProviderWithoutIssuerUri_ShouldNotIncludeProvider() {
        // Arrange
        OAuth2Config configWithoutIssuerUri = new OAuth2Config(oAuth2UserService, jwtService);
        ReflectionTestUtils.setField(configWithoutIssuerUri, "customClientId", "test-custom-client-id");
        ReflectionTestUtils.setField(configWithoutIssuerUri, "customClientSecret", "test-custom-client-secret");
        ReflectionTestUtils.setField(configWithoutIssuerUri, "customIssuerUri", null);
        ReflectionTestUtils.setField(configWithoutIssuerUri, "redirectUri", "http://localhost:8080/login/oauth2/code/");

        // Act
        ClientRegistrationRepository repository = configWithoutIssuerUri.clientRegistrationRepository();

        // Assert
        assertNull(repository.findByRegistrationId("custom"));
    }

    @Test
    void clientRegistrationRepository_ShouldConfigureCorrectRedirectUris() {
        // Act
        ClientRegistrationRepository repository = oauth2Config.clientRegistrationRepository();

        // Assert
        ClientRegistration googleRegistration = repository.findByRegistrationId("google");
        assertEquals("http://localhost:8080/login/oauth2/code/google", googleRegistration.getRedirectUri());

        ClientRegistration microsoftRegistration = repository.findByRegistrationId("microsoft");
        assertEquals("http://localhost:8080/login/oauth2/code/microsoft", microsoftRegistration.getRedirectUri());

        ClientRegistration githubRegistration = repository.findByRegistrationId("github");
        assertEquals("http://localhost:8080/login/oauth2/code/github", githubRegistration.getRedirectUri());

        ClientRegistration customRegistration = repository.findByRegistrationId("custom");
        assertEquals("http://localhost:8080/login/oauth2/code/custom", customRegistration.getRedirectUri());
    }

    @Test
    void clientRegistrationRepository_ShouldConfigureCorrectProviderUris() {
        // Act
        ClientRegistrationRepository repository = oauth2Config.clientRegistrationRepository();

        // Assert Google URIs
        ClientRegistration googleRegistration = repository.findByRegistrationId("google");
        assertEquals("https://accounts.google.com/o/oauth2/v2/auth", googleRegistration.getProviderDetails().getAuthorizationUri());
        assertEquals("https://www.googleapis.com/oauth2/v4/token", googleRegistration.getProviderDetails().getTokenUri());
        assertEquals("https://www.googleapis.com/oauth2/v3/userinfo", googleRegistration.getProviderDetails().getUserInfoEndpoint().getUri());
        assertEquals("https://www.googleapis.com/oauth2/v3/certs", googleRegistration.getProviderDetails().getJwkSetUri());

        // Assert Microsoft URIs
        ClientRegistration microsoftRegistration = repository.findByRegistrationId("microsoft");
        assertEquals("https://login.microsoftonline.com/common/oauth2/v2.0/authorize", microsoftRegistration.getProviderDetails().getAuthorizationUri());
        assertEquals("https://login.microsoftonline.com/common/oauth2/v2.0/token", microsoftRegistration.getProviderDetails().getTokenUri());
        assertEquals("https://graph.microsoft.com/oidc/userinfo", microsoftRegistration.getProviderDetails().getUserInfoEndpoint().getUri());
        assertEquals("https://login.microsoftonline.com/common/discovery/v2.0/keys", microsoftRegistration.getProviderDetails().getJwkSetUri());

        // Assert GitHub URIs
        ClientRegistration githubRegistration = repository.findByRegistrationId("github");
        assertEquals("https://github.com/login/oauth/authorize", githubRegistration.getProviderDetails().getAuthorizationUri());
        assertEquals("https://github.com/login/oauth/access_token", githubRegistration.getProviderDetails().getTokenUri());
        assertEquals("https://api.github.com/user", githubRegistration.getProviderDetails().getUserInfoEndpoint().getUri());
    }

    @Test
    void clientRegistrationRepository_ShouldConfigureCorrectUserNameAttributes() {
        // Act
        ClientRegistrationRepository repository = oauth2Config.clientRegistrationRepository();

        // Assert
        ClientRegistration googleRegistration = repository.findByRegistrationId("google");
        assertEquals("sub", googleRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName());

        ClientRegistration microsoftRegistration = repository.findByRegistrationId("microsoft");
        assertEquals("sub", microsoftRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName());

        ClientRegistration githubRegistration = repository.findByRegistrationId("github");
        assertEquals("id", githubRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName());

        ClientRegistration customRegistration = repository.findByRegistrationId("custom");
        assertEquals("sub", customRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName());
    }
}