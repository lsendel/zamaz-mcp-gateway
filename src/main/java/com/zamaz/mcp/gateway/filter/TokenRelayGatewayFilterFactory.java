package com.zamaz.mcp.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Gateway filter for relaying OAuth2 access tokens to downstream services.
 * Extracts the token from the security context and adds it to outgoing requests.
 */
@Component
public class TokenRelayGatewayFilterFactory extends AbstractGatewayFilterFactory<TokenRelayGatewayFilterFactory.Config> {
    
    private static final Logger logger = LoggerFactory.getLogger(TokenRelayGatewayFilterFactory.class);
    
    private final ReactiveOAuth2AuthorizedClientService authorizedClientService;
    
    public TokenRelayGatewayFilterFactory(ReactiveOAuth2AuthorizedClientService authorizedClientService) {
        super(Config.class);
        this.authorizedClientService = authorizedClientService;
    }
    
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> ReactiveSecurityContextHolder.getContext()
            .map(SecurityContext::getAuthentication)
            .flatMap(authentication -> extractToken(authentication, exchange))
            .map(token -> withBearerAuth(exchange, token))
            .defaultIfEmpty(exchange)
            .flatMap(chain::filter);
    }
    
    /**
     * Extract OAuth2 token from authentication
     */
    private Mono<String> extractToken(Authentication authentication, ServerWebExchange exchange) {
        // Check if it's already a JWT token (API request)
        if (authentication instanceof JwtAuthenticationToken) {
            JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) authentication;
            Jwt jwt = jwtAuth.getToken();
            return Mono.just(jwt.getTokenValue());
        }
        
        // Check if it's an OAuth2 authentication (UI login)
        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            String clientRegistrationId = oauthToken.getAuthorizedClientRegistrationId();
            
            return authorizedClientService.loadAuthorizedClient(
                    clientRegistrationId, 
                    authentication.getName()
                )
                .map(OAuth2AuthorizedClient::getAccessToken)
                .map(OAuth2AccessToken::getTokenValue)
                .doOnNext(token -> logger.debug("Relaying OAuth2 token for user: {}", 
                    authentication.getName()));
        }
        
        // Check if there's already a Bearer token in the request
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return Mono.just(authHeader.substring(7));
        }
        
        logger.debug("No token found for authentication type: {}", 
            authentication.getClass().getSimpleName());
        return Mono.empty();
    }
    
    /**
     * Add Bearer token to outgoing request
     */
    private ServerWebExchange withBearerAuth(ServerWebExchange exchange, String token) {
        return exchange.mutate()
            .request(r -> r.headers(headers -> 
                headers.setBearerAuth(token)))
            .build();
    }
    
    public static class Config {
        // Configuration properties if needed
        private boolean removeOriginalAuth = true;
        
        public boolean isRemoveOriginalAuth() {
            return removeOriginalAuth;
        }
        
        public void setRemoveOriginalAuth(boolean removeOriginalAuth) {
            this.removeOriginalAuth = removeOriginalAuth;
        }
    }
}