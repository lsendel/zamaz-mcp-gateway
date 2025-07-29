package com.zamaz.mcp.gateway.security;

import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

/**
 * Custom authentication success handler for OAuth2 login.
 * Redirects to the original requested URL after successful authentication.
 */
public class RedirectServerAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {
    
    private final String defaultTargetUrl;
    
    public RedirectServerAuthenticationSuccessHandler(String defaultTargetUrl) {
        this.defaultTargetUrl = defaultTargetUrl;
    }
    
    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, 
                                            Authentication authentication) {
        ServerWebExchange exchange = webFilterExchange.getExchange();
        ServerHttpResponse response = exchange.getResponse();
        
        // Get the original requested URL from session or use default
        String targetUrl = getTargetUrl(exchange);
        
        // Set redirect
        response.setStatusCode(org.springframework.http.HttpStatus.FOUND);
        response.getHeaders().setLocation(URI.create(targetUrl));
        
        return response.setComplete();
    }
    
    private String getTargetUrl(ServerWebExchange exchange) {
        // Try to get the original requested URL from query parameter
        String redirectUri = exchange.getRequest().getQueryParams().getFirst("redirect_uri");
        if (redirectUri != null && !redirectUri.isEmpty()) {
            return redirectUri;
        }
        
        // Otherwise use default
        return defaultTargetUrl;
    }
}