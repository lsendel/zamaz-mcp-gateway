package com.zamaz.mcp.gateway.config;

import com.zamaz.mcp.gateway.filter.RateLimitingGatewayFilterFactory;
import com.zamaz.mcp.gateway.filter.RequestValidationGatewayFilterFactory;
import com.zamaz.mcp.gateway.filter.SecurityHeadersGatewayFilterFactory;
import com.zamaz.mcp.gateway.filter.TokenRelayGatewayFilterFactory;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;

/**
 * Additional gateway configuration for custom routes and filters.
 */
@Configuration
public class GatewayConfiguration {
    
    /**
     * Fallback route configuration for circuit breaker
     */
    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder,
                                         RequestValidationGatewayFilterFactory requestValidation,
                                         SecurityHeadersGatewayFilterFactory securityHeaders,
                                         RateLimitingGatewayFilterFactory rateLimiting,
                                         TokenRelayGatewayFilterFactory tokenRelay) {
        return builder.routes()
            // Fallback route for circuit breaker
            .route("fallback", r -> r
                .path("/fallback/**")
                .filters(f -> f
                    .setStatus(503)
                    .setBody("{\"error\": \"Service temporarily unavailable\", \"message\": \"Please try again later\"}")
                    .removeRequestHeader("Authorization")
                )
                .uri("no://op")
            )
            
            // Health check endpoints (no authentication required)
            .route("health", r -> r
                .path("/health", "/actuator/health/**")
                .filters(f -> f
                    .filter(securityHeaders.apply(new SecurityHeadersGatewayFilterFactory.Config()))
                )
                .uri("no://op")
            )
            
            // API documentation routes
            .route("api-docs", r -> r
                .path("/v3/api-docs/**", "/swagger-ui/**", "/webjars/**")
                .and()
                .method(HttpMethod.GET)
                .filters(f -> f
                    .filter(rateLimiting.apply(createRateLimitConfig(50, 100)))
                )
                .uri("no://op")
            )
            
            .build();
    }
    
    private RateLimitingGatewayFilterFactory.Config createRateLimitConfig(int rate, int burst) {
        RateLimitingGatewayFilterFactory.Config config = new RateLimitingGatewayFilterFactory.Config();
        config.setReplenishRate(rate);
        config.setBurstCapacity(burst);
        config.setKeyResolver(RateLimitingGatewayFilterFactory.Config.KeyResolver.IP);
        return config;
    }
}