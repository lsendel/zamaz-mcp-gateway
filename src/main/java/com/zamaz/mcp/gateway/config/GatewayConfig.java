package com.zamaz.mcp.gateway.config;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Collections;

/**
 * Gateway configuration
 */
@Configuration
public class GatewayConfig {
    
    /**
     * Configure CORS for the gateway with security restrictions
     */
    @Bean
    public CorsWebFilter corsFilter() {
        CorsConfiguration corsConfig = new CorsConfiguration();
        
        // Restrict to specific domains in production
        String allowedOrigins = System.getenv("ALLOWED_ORIGINS");
        if (allowedOrigins != null && !allowedOrigins.trim().isEmpty()) {
            corsConfig.setAllowedOrigins(Arrays.asList(allowedOrigins.split(",")));
        } else {
            // Development fallback - restrict in production
            corsConfig.setAllowedOriginPatterns(Collections.singletonList("http://localhost:*"));
        }
        
        corsConfig.setMaxAge(3600L);
        corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        
        // Restrict headers for security
        corsConfig.setAllowedHeaders(Arrays.asList(
            "Authorization", 
            "Content-Type", 
            "X-Requested-With",
            "X-Organization-ID",
            "X-Request-ID"
        ));
        
        // Expose necessary headers
        corsConfig.setExposedHeaders(Arrays.asList(
            "X-Total-Count",
            "X-Rate-Limit-Remaining",
            "X-Request-ID"
        ));
        
        corsConfig.setAllowCredentials(true);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);
        
        return new CorsWebFilter(source);
    }
    
    /**
     * Configure rate limiter
     */
    @Bean
    public RedisRateLimiter redisRateLimiter() {
        return new RedisRateLimiter(100, 200, 1); // 100 requests per second, burst of 200
    }
    
    /**
     * Key resolver for rate limiting based on user ID
     */
    @Bean
    public KeyResolver userKeyResolver() {
        return exchange -> {
            String userId = exchange.getRequest().getHeaders().getFirst("X-User-ID");
            return userId != null ? Mono.just(userId) : Mono.just("anonymous");
        };
    }
    
    /**
     * Key resolver for rate limiting based on IP address
     */
    @Bean
    public KeyResolver ipKeyResolver() {
        return exchange -> {
            String ip = exchange.getRequest().getRemoteAddress() != null 
                ? exchange.getRequest().getRemoteAddress().getAddress().getHostAddress()
                : "unknown";
            return Mono.just(ip);
        };
    }
    
    /**
     * WebClient builder for making HTTP calls to downstream services
     */
    @Bean
    public WebClient.Builder webClientBuilder() {
        return WebClient.builder()
            .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(1024 * 1024)); // 1MB
    }
}