package com.zamaz.mcp.gateway.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Collections;

/**
 * WebSocket configuration for API Gateway
 */
@Configuration
@Slf4j
public class WebSocketConfig {
    
    private static final String WS_BACKEND_URI = "ws://mcp-debate:8085";
    private static final String WS_PATH_PATTERN = "/ws/**";
    
    /**
     * Configure WebSocket routes
     */
    @Bean
    public RouteLocator webSocketRoutes(RouteLocatorBuilder builder, 
                                       RedisRateLimiter rateLimiter,
                                       KeyResolver userKeyResolver) {
        return builder.routes()
            // WebSocket route for debate real-time updates
            .route("debate-websocket", r -> r
                .path("/api/v1/debates/*/ws")
                .filters(f -> f
                    // Add authentication filter
                    .filter((exchange, chain) -> {
                        String token = extractToken(exchange.getRequest().getHeaders());
                        if (token == null) {
                            exchange.getResponse().setRawStatusCode(401);
                            return exchange.getResponse().setComplete();
                        }
                        
                        // Add token to WebSocket handshake headers
                        exchange.getRequest().mutate()
                            .header("X-Auth-Token", token)
                            .build();
                        
                        return chain.filter(exchange);
                    })
                    // Add organization header
                    .addRequestHeader("X-Organization-ID", 
                        exchange -> exchange.getRequest().getHeaders()
                            .getFirst("X-Organization-ID"))
                    // Add request ID for tracing
                    .addRequestHeader("X-Request-ID", 
                        exchange -> java.util.UUID.randomUUID().toString())
                    // Log WebSocket connections
                    .filter((exchange, chain) -> {
                        String path = exchange.getRequest().getPath().value();
                        log.info("WebSocket connection established: {}", path);
                        return chain.filter(exchange)
                            .doFinally(signal -> 
                                log.info("WebSocket connection closed: {} - {}", 
                                    path, signal));
                    })
                    // Apply rate limiting to WebSocket connections
                    .requestRateLimiter(config -> config
                        .setRateLimiter(rateLimiter)
                        .setKeyResolver(userKeyResolver)
                        .setDenyEmptyKey(true))
                )
                .uri(WS_BACKEND_URI))
            
            // General WebSocket route for other real-time features
            .route("general-websocket", r -> r
                .path(WS_PATH_PATTERN)
                .filters(f -> f
                    .filter((exchange, chain) -> {
                        String token = extractToken(exchange.getRequest().getHeaders());
                        if (token == null) {
                            exchange.getResponse().setRawStatusCode(401);
                            return exchange.getResponse().setComplete();
                        }
                        
                        exchange.getRequest().mutate()
                            .header("X-Auth-Token", token)
                            .build();
                        
                        return chain.filter(exchange);
                    })
                    .addRequestHeader("X-Request-ID", 
                        exchange -> java.util.UUID.randomUUID().toString())
                )
                .uri(WS_BACKEND_URI))
            
            // Server-Sent Events (SSE) route for fallback
            .route("sse-events", r -> r
                .path("/api/v1/events/**")
                .filters(f -> f
                    .addRequestHeader("Accept", "text/event-stream")
                    .addRequestHeader("Cache-Control", "no-cache")
                    .addRequestHeader("X-Accel-Buffering", "no")
                )
                .uri("http://mcp-debate:8085"))
            
            .build();
    }
    
    /**
     * Configure CORS for WebSocket connections
     */
    @Bean
    public CorsWebFilter corsWebSocketFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(Arrays.asList(
            "http://localhost:*",
            "https://localhost:*",
            "http://127.0.0.1:*",
            "https://127.0.0.1:*"
        ));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(Arrays.asList(
            "*",
            "Authorization",
            "X-Organization-ID",
            "X-Auth-Token",
            "Upgrade",
            "Connection",
            "Sec-WebSocket-Key",
            "Sec-WebSocket-Version",
            "Sec-WebSocket-Extensions"
        ));
        config.setExposedHeaders(Arrays.asList(
            "X-Request-ID",
            "X-RateLimit-Remaining",
            "X-RateLimit-Retry-After-Seconds"
        ));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        
        return new CorsWebFilter(source);
    }
    
    /**
     * Key resolver for WebSocket rate limiting
     */
    @Bean
    public KeyResolver webSocketUserKeyResolver() {
        return exchange -> {
            String token = extractToken(exchange.getRequest().getHeaders());
            if (token != null) {
                // In production, decode JWT to get user ID
                // For now, use token hash as key
                return Mono.just(String.valueOf(token.hashCode()));
            }
            return Mono.just("anonymous");
        };
    }
    
    /**
     * Configure WebSocket-specific rate limiter
     */
    @Bean
    public RedisRateLimiter webSocketRateLimiter() {
        return new RedisRateLimiter(
            10,  // replenishRate: 10 connections per second
            20,  // burstCapacity: allow burst of 20 connections
            1    // requestedTokens: 1 token per connection
        );
    }
    
    /**
     * Extract token from headers
     */
    private String extractToken(HttpHeaders headers) {
        String authorization = headers.getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.startsWith("Bearer ")) {
            return authorization.substring(7);
        }
        
        // Check for token in query parameters (for WebSocket connections)
        String token = headers.getFirst("X-Auth-Token");
        if (token != null) {
            return token;
        }
        
        return null;
    }
}