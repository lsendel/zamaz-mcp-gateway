package com.zamaz.mcp.gateway.config;

import com.zamaz.mcp.gateway.service.OAuth2UserService;
import com.zamaz.mcp.security.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * OAuth2 and SSO configuration for the MCP Gateway.
 * Supports multiple OAuth2 providers: Google, Microsoft, GitHub, and custom OIDC providers.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
public class OAuth2Config {

    private final OAuth2UserService oAuth2UserService;
    private final JwtService jwtService;

    @Value("${oauth2.google.client-id:}")
    private String googleClientId;

    @Value("${oauth2.google.client-secret:}")
    private String googleClientSecret;

    @Value("${oauth2.microsoft.client-id:}")
    private String microsoftClientId;

    @Value("${oauth2.microsoft.client-secret:}")
    private String microsoftClientSecret;

    @Value("${oauth2.github.client-id:}")
    private String githubClientId;

    @Value("${oauth2.github.client-secret:}")
    private String githubClientSecret;

    @Value("${oauth2.custom.client-id:}")
    private String customClientId;

    @Value("${oauth2.custom.client-secret:}")
    private String customClientSecret;

    @Value("${oauth2.custom.issuer-uri:}")
    private String customIssuerUri;

    @Value("${oauth2.custom.jwk-set-uri:}")
    private String customJwkSetUri;

    @Value("${oauth2.redirect-uri:http://localhost:8080/login/oauth2/code/}")
    private String redirectUri;

    @Value("${oauth2.success-redirect-uri:http://localhost:3000/dashboard}")
    private String successRedirectUri;

    @Value("${oauth2.failure-redirect-uri:http://localhost:3000/login?error=oauth2}")
    private String failureRedirectUri;

    @Value("${jwt.secret}")
    private String jwtSecret;

    /**
     * Configure OAuth2 client registrations for supported providers.
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        var registrations = new java.util.ArrayList<ClientRegistration>();

        // Google OAuth2 configuration
        if (isConfigured(googleClientId, googleClientSecret)) {
            registrations.add(
                ClientRegistration.withRegistrationId("google")
                    .clientId(googleClientId)
                    .clientSecret(googleClientSecret)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri(redirectUri + "google")
                    .scope("openid", "profile", "email")
                    .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
                    .tokenUri("https://www.googleapis.com/oauth2/v4/token")
                    .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
                    .userNameAttributeName(IdTokenClaimNames.SUB)
                    .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
                    .clientName("Google")
                    .build()
            );
            log.info("Google OAuth2 provider configured");
        }

        // Microsoft Azure AD OAuth2 configuration
        if (isConfigured(microsoftClientId, microsoftClientSecret)) {
            registrations.add(
                ClientRegistration.withRegistrationId("microsoft")
                    .clientId(microsoftClientId)
                    .clientSecret(microsoftClientSecret)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri(redirectUri + "microsoft")
                    .scope("openid", "profile", "email")
                    .authorizationUri("https://login.microsoftonline.com/common/oauth2/v2.0/authorize")
                    .tokenUri("https://login.microsoftonline.com/common/oauth2/v2.0/token")
                    .userInfoUri("https://graph.microsoft.com/oidc/userinfo")
                    .userNameAttributeName("sub")
                    .jwkSetUri("https://login.microsoftonline.com/common/discovery/v2.0/keys")
                    .clientName("Microsoft")
                    .build()
            );
            log.info("Microsoft OAuth2 provider configured");
        }

        // GitHub OAuth2 configuration
        if (isConfigured(githubClientId, githubClientSecret)) {
            registrations.add(
                ClientRegistration.withRegistrationId("github")
                    .clientId(githubClientId)
                    .clientSecret(githubClientSecret)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri(redirectUri + "github")
                    .scope("user:email", "read:user")
                    .authorizationUri("https://github.com/login/oauth/authorize")
                    .tokenUri("https://github.com/login/oauth/access_token")
                    .userInfoUri("https://api.github.com/user")
                    .userNameAttributeName("id")
                    .clientName("GitHub")
                    .build()
            );
            log.info("GitHub OAuth2 provider configured");
        }

        // Custom OIDC provider configuration
        if (isConfigured(customClientId, customClientSecret) && customIssuerUri != null) {
            registrations.add(
                ClientRegistration.withRegistrationId("custom")
                    .clientId(customClientId)
                    .clientSecret(customClientSecret)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri(redirectUri + "custom")
                    .scope("openid", "profile", "email")
                    .authorizationUri(customIssuerUri + "/auth")
                    .tokenUri(customIssuerUri + "/token")
                    .userInfoUri(customIssuerUri + "/userinfo")
                    .userNameAttributeName("sub")
                    .jwkSetUri(customJwkSetUri != null ? customJwkSetUri : customIssuerUri + "/certs")
                    .clientName("Custom OIDC")
                    .build()
            );
            log.info("Custom OIDC provider configured");
        }

        if (registrations.isEmpty()) {
            log.warn("No OAuth2 providers configured. OAuth2 login will be disabled.");
            // Return empty repository to avoid startup errors
            return new InMemoryClientRegistrationRepository();
        }

        return new InMemoryClientRegistrationRepository(registrations);
    }

    /**
     * Configure JWT decoder for validating tokens from custom OIDC providers.
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        // Use the same secret as JWT service for consistency
        var keySpec = new SecretKeySpec(
            jwtSecret.getBytes(StandardCharsets.UTF_8), 
            "HmacSHA256"
        );
        return NimbusJwtDecoder.withSecretKey(keySpec).build();
    }

    /**
     * OAuth2 login success handler.
     */
    @Bean
    public AuthenticationSuccessHandler oauth2SuccessHandler() {
        return (request, response, authentication) -> {
            log.info("OAuth2 login successful for user: {}", authentication.getName());
            
            // Generate JWT token for the authenticated user
            String jwtToken = jwtService.generateToken(authentication.getName());
            
            // Add token to response header
            response.addHeader("Authorization", "Bearer " + jwtToken);
            
            // Redirect to success page with token in URL (for frontend consumption)
            String redirectUrl = successRedirectUri + "?token=" + jwtToken;
            response.sendRedirect(redirectUrl);
        };
    }

    /**
     * OAuth2 login failure handler.
     */
    @Bean
    public AuthenticationFailureHandler oauth2FailureHandler() {
        return (request, response, exception) -> {
            log.error("OAuth2 login failed", exception);
            
            // Redirect to failure page with error message
            String redirectUrl = failureRedirectUri + "&message=" + 
                java.net.URLEncoder.encode(exception.getMessage(), StandardCharsets.UTF_8);
            response.sendRedirect(redirectUrl);
        };
    }

    /**
     * Configure OAuth2 security filter chain.
     */
    @Bean
    public SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .oauth2Login(oauth2 -> oauth2
                .clientRegistrationRepository(clientRegistrationRepository())
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(oAuth2UserService)
                )
                .successHandler(oauth2SuccessHandler())
                .failureHandler(oauth2FailureHandler())
                .loginPage("/oauth2/authorization")
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder())
                )
            );

        return http.build();
    }

    /**
     * Check if OAuth2 provider is configured.
     */
    private boolean isConfigured(String clientId, String clientSecret) {
        return clientId != null && !clientId.trim().isEmpty() && 
               clientSecret != null && !clientSecret.trim().isEmpty();
    }
}