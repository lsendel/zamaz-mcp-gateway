package com.zamaz.mcp.gateway.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.logout.RedirectServerLogoutSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

/**
 * OAuth2 security configuration for the API Gateway.
 * Configures the gateway as both an OAuth2 client and resource server.
 */
@Configuration
@EnableWebFluxSecurity
public class OAuth2SecurityConfig {
    
    @Value("${security.oauth2.authorization-server-url:http://localhost:9000}")
    private String authorizationServerUrl;
    
    @Value("${security.oauth2.client.registration.gateway.client-id:mcp-gateway}")
    private String clientId;
    
    @Value("${security.oauth2.client.registration.gateway.client-secret:gateway-secret}")
    private String clientSecret;
    
    @Value("${security.cors.allowed-origins:http://localhost:3000,http://localhost:3001}")
    private List<String> allowedOrigins;
    
    /**
     * Main security filter chain configuration
     */
    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(
            ServerHttpSecurity http,
            ReactiveJwtDecoder jwtDecoder,
            ReactiveClientRegistrationRepository clientRegistrationRepository) {
        
        return http
            // CORS configuration
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            
            // CSRF disabled for API Gateway (stateless)
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            
            // Security headers
            .headers(headers -> headers
                .frameOptions(frameOptions -> 
                    frameOptions.mode(XFrameOptionsServerHttpHeadersWriter.Mode.DENY))
                .contentSecurityPolicy(csp -> 
                    csp.policyDirectives("default-src 'self'; frame-ancestors 'none';"))
                .hsts(hsts -> hsts
                    .includeSubdomains(true)
                    .maxAge(java.time.Duration.ofDays(365)))
            )
            
            // Authorization rules
            .authorizeExchange(exchanges -> exchanges
                // Public endpoints
                .pathMatchers("/", "/health", "/actuator/health/**").permitAll()
                .pathMatchers("/api/v*/auth/login", "/api/v*/auth/register").permitAll()
                .pathMatchers("/oauth2/**", "/login/**", "/error").permitAll()
                .pathMatchers("/webjars/**", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
                
                // WebSocket endpoints require authentication
                .pathMatchers("/ws/**").authenticated()
                
                // All other endpoints require authentication
                .anyExchange().authenticated()
            )
            
            // OAuth2 Resource Server configuration (for API requests with Bearer tokens)
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.decoder(jwtDecoder))
            )
            
            // OAuth2 Client configuration (for UI login flow)
            .oauth2Login(oauth2 -> oauth2
                .authenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler("/"))
            )
            
            // Logout configuration
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessHandler(logoutSuccessHandler())
            )
            
            // Stateless session management
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            
            .build();
    }
    
    /**
     * JWT decoder for validating access tokens
     */
    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        return NimbusReactiveJwtDecoder
            .withJwkSetUri(authorizationServerUrl + "/.well-known/jwks.json")
            .build();
    }
    
    /**
     * OAuth2 authorized client repository
     */
    @Bean
    public ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new WebSessionServerOAuth2AuthorizedClientRepository();
    }
    
    /**
     * CORS configuration
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(allowedOrigins);
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList(
            "Authorization", "Content-Type", "X-Organization-ID", "X-Request-ID"));
        configuration.setExposedHeaders(Arrays.asList("X-Request-ID"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        
        return source;
    }
    
    /**
     * Logout success handler
     */
    @Bean
    public ServerLogoutSuccessHandler logoutSuccessHandler() {
        RedirectServerLogoutSuccessHandler handler = new RedirectServerLogoutSuccessHandler();
        handler.setLogoutSuccessUrl(URI.create("/"));
        return handler;
    }
}