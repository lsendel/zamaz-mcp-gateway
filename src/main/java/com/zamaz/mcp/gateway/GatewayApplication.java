package com.zamaz.mcp.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;

/**
 * MCP API Gateway Application
 * Provides centralized routing, authentication, and cross-cutting concerns
 */
@SpringBootApplication
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

    /**
     * Configure routes for all MCP services
     */
    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
            // Organization Service Routes
            .route("organization-service", r -> r
                .path("/api/v1/organizations/**", "/api/v1/auth/**")
                .filters(f -> f
                    .circuitBreaker(config -> config
                        .setName("organization-cb")
                        .setFallbackUri("forward:/fallback/organization"))
                    .retry(config -> config.setRetries(3))
                    .requestRateLimiter(config -> config
                        .setRateLimiter(redisRateLimiter())
                        .setKeyResolver(userKeyResolver())))
                .uri("http://mcp-organization:5005"))
            
            // LLM Service Routes
            .route("llm-service", r -> r
                .path("/api/v1/llm/**", "/api/v1/completions/**", "/api/v1/providers/**")
                .filters(f -> f
                    .circuitBreaker(config -> config
                        .setName("llm-cb")
                        .setFallbackUri("forward:/fallback/llm"))
                    .retry(config -> config.setRetries(2))
                    .requestRateLimiter(config -> config
                        .setRateLimiter(redisRateLimiter())
                        .setKeyResolver(userKeyResolver())))
                .uri("http://mcp-llm:5002"))
            
            // Controller/Debate Service Routes
            .route("controller-service", r -> r
                .path("/api/v1/debates/**", "/api/v1/rounds/**")
                .filters(f -> f
                    .circuitBreaker(config -> config
                        .setName("controller-cb")
                        .setFallbackUri("forward:/fallback/controller"))
                    .retry(config -> config.setRetries(3))
                    .requestRateLimiter(config -> config
                        .setRateLimiter(redisRateLimiter())
                        .setKeyResolver(userKeyResolver())))
                .uri("http://mcp-controller:5013"))
            
            // RAG Service Routes
            .route("rag-service", r -> r
                .path("/api/v1/rag/**", "/api/v1/knowledge/**", "/api/v1/search/**")
                .filters(f -> f
                    .circuitBreaker(config -> config
                        .setName("rag-cb")
                        .setFallbackUri("forward:/fallback/rag"))
                    .retry(config -> config.setRetries(2))
                    .requestRateLimiter(config -> config
                        .setRateLimiter(redisRateLimiter())
                        .setKeyResolver(userKeyResolver())))
                .uri("http://mcp-rag:5004"))
            
            // Template Service Routes
            .route("template-service", r -> r
                .path("/api/v1/templates/**")
                .filters(f -> f
                    .circuitBreaker(config -> config
                        .setName("template-cb")
                        .setFallbackUri("forward:/fallback/template"))
                    .retry(config -> config.setRetries(3))
                    .requestRateLimiter(config -> config
                        .setRateLimiter(redisRateLimiter())
                        .setKeyResolver(userKeyResolver())))
                .uri("http://mcp-template:5006"))
            
            // Health Check Aggregation
            .route("health-check", r -> r
                .path("/health/**")
                .filters(f -> f.stripPrefix(1))
                .uri("http://localhost:8080"))
            
            build();
    }

    @Bean
    public RedisRateLimiter redisRateLimiter() {
        return new RedisRateLimiter(100, 200, 1); // 100 requests per second, burst of 200
    }

    @Bean
    public KeyResolver userKeyResolver() {
        return exchange -> exchange.getRequest().getHeaders()
            .getFirst("X-User-ID") != null ? 
            Mono.just(exchange.getRequest().getHeaders().getFirst("X-User-ID")) :
            Mono.just("anonymous");
    }
}