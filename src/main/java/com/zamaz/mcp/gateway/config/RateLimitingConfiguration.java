package com.zamaz.mcp.gateway.config;

import com.zamaz.mcp.gateway.filter.GlobalRateLimitFilter;
import com.zamaz.mcp.security.jwt.JwtService;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Configuration for API rate limiting across all endpoints.
 * Implements tiered rate limiting based on authentication status and user roles.
 */
@Configuration
@Slf4j
public class RateLimitingConfiguration {

    @Value("${app.rate-limit.anonymous.capacity:50}")
    private int anonymousCapacity;
    
    @Value("${app.rate-limit.anonymous.duration:PT1M}")
    private Duration anonymousDuration;
    
    @Value("${app.rate-limit.authenticated.capacity:200}")
    private int authenticatedCapacity;
    
    @Value("${app.rate-limit.authenticated.duration:PT1M}")
    private Duration authenticatedDuration;
    
    @Value("${app.rate-limit.admin.capacity:1000}")
    private int adminCapacity;
    
    @Value("${app.rate-limit.admin.duration:PT1M}")
    private Duration adminDuration;
    
    @Value("${app.rate-limit.organization.capacity:5000}")
    private int organizationCapacity;
    
    @Value("${app.rate-limit.organization.duration:PT1M}")
    private Duration organizationDuration;

    @Bean
    public GlobalRateLimitFilter globalRateLimitFilter(
            JwtService jwtService, 
            RedisTemplate<String, Object> redisTemplate) {
        return new GlobalRateLimitFilter(jwtService, redisTemplate, this);
    }

    /**
     * Get rate limit configuration for anonymous users
     */
    public RateLimitConfig getAnonymousConfig() {
        return new RateLimitConfig(anonymousCapacity, anonymousDuration);
    }

    /**
     * Get rate limit configuration for authenticated users
     */
    public RateLimitConfig getAuthenticatedConfig() {
        return new RateLimitConfig(authenticatedCapacity, authenticatedDuration);
    }

    /**
     * Get rate limit configuration for admin users
     */
    public RateLimitConfig getAdminConfig() {
        return new RateLimitConfig(adminCapacity, adminDuration);
    }

    /**
     * Get rate limit configuration for organizations
     */
    public RateLimitConfig getOrganizationConfig() {
        return new RateLimitConfig(organizationCapacity, organizationDuration);
    }

    /**
     * Rate limit configuration
     */
    public static class RateLimitConfig {
        private final int capacity;
        private final Duration duration;
        
        public RateLimitConfig(int capacity, Duration duration) {
            this.capacity = capacity;
            this.duration = duration;
        }
        
        public int getCapacity() { return capacity; }
        public Duration getDuration() { return duration; }
        
        public Bandwidth toBandwidth() {
            return Bandwidth.classic(capacity, Refill.intervally(capacity, duration));
        }
    }
}

/**
 * Global rate limiting filter implementation
 */
@Slf4j
class GlobalRateLimitFilter implements GlobalFilter, Ordered {
    
    private final JwtService jwtService;
    private final RedisTemplate<String, Object> redisTemplate;
    private final RateLimitingConfiguration config;
    private final Map<String, Bucket> bucketCache = new ConcurrentHashMap<>();
    
    private static final String RATE_LIMIT_PREFIX = "rate_limit:";
    private static final String HEADER_LIMIT = "X-RateLimit-Limit";
    private static final String HEADER_REMAINING = "X-RateLimit-Remaining";
    private static final String HEADER_RESET = "X-RateLimit-Reset";
    
    public GlobalRateLimitFilter(JwtService jwtService, RedisTemplate<String, Object> redisTemplate, 
                                RateLimitingConfiguration config) {
        this.jwtService = jwtService;
        this.redisTemplate = redisTemplate;
        this.config = config;
    }
    
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        
        // Skip rate limiting for health checks
        if (request.getPath().value().startsWith("/actuator")) {
            return chain.filter(exchange);
        }
        
        String key = resolveKey(request);
        RateLimitingConfiguration.RateLimitConfig rateLimitConfig = resolveConfig(request);
        Bucket bucket = resolveBucket(key, rateLimitConfig);
        
        if (bucket.tryConsume(1)) {
            // Add rate limit headers
            ServerHttpResponse response = exchange.getResponse();
            response.getHeaders().add(HEADER_LIMIT, String.valueOf(rateLimitConfig.getCapacity()));
            response.getHeaders().add(HEADER_REMAINING, String.valueOf(bucket.getAvailableTokens()));
            response.getHeaders().add(HEADER_RESET, String.valueOf(
                System.currentTimeMillis() + rateLimitConfig.getDuration().toMillis()
            ));
            
            return chain.filter(exchange);
        } else {
            // Rate limit exceeded
            return handleRateLimitExceeded(exchange, key, rateLimitConfig);
        }
    }
    
    @Override
    public int getOrder() {
        return -100; // Run early in the filter chain
    }
    
    private String resolveKey(ServerHttpRequest request) {
        String token = extractToken(request);
        
        if (token != null && jwtService.isTokenValid(token)) {
            // Authenticated user
            String userId = jwtService.extractUserId(token);
            String orgId = jwtService.extractOrganizationId(token);
            
            // Organization-level rate limiting takes precedence
            if (orgId != null) {
                return RATE_LIMIT_PREFIX + "org:" + orgId;
            }
            
            return RATE_LIMIT_PREFIX + "user:" + userId;
        }
        
        // Anonymous user - rate limit by IP
        return RATE_LIMIT_PREFIX + "ip:" + getClientIp(request);
    }
    
    private RateLimitingConfiguration.RateLimitConfig resolveConfig(ServerHttpRequest request) {
        String token = extractToken(request);
        
        if (token != null && jwtService.isTokenValid(token)) {
            var roles = jwtService.extractRoles(token);
            
            // Check for admin role
            if (roles != null && roles.stream().anyMatch(role -> 
                    role.equalsIgnoreCase("ADMIN") || role.equalsIgnoreCase("SUPER_ADMIN"))) {
                return config.getAdminConfig();
            }
            
            // Authenticated user
            return config.getAuthenticatedConfig();
        }
        
        // Anonymous user
        return config.getAnonymousConfig();
    }
    
    private Bucket resolveBucket(String key, RateLimitingConfiguration.RateLimitConfig rateLimitConfig) {
        return bucketCache.computeIfAbsent(key, k -> 
            Bucket.builder()
                .addLimit(rateLimitConfig.toBandwidth())
                .build()
        );
    }
    
    private Mono<Void> handleRateLimitExceeded(ServerWebExchange exchange, String key, 
                                               RateLimitingConfiguration.RateLimitConfig config) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        response.getHeaders().add("Retry-After", String.valueOf(config.getDuration().getSeconds()));
        
        String body = String.format(
            "{\"error\":\"Rate limit exceeded\",\"message\":\"Too many requests. Please try again in %d seconds.\",\"retryAfter\":%d}",
            config.getDuration().getSeconds(),
            config.getDuration().getSeconds()
        );
        
        var buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        
        log.warn("Rate limit exceeded for key: {}", key);
        
        // Track violations in Redis
        try {
            String violationKey = "rate_violations:" + key;
            redisTemplate.opsForValue().increment(violationKey);
            redisTemplate.expire(violationKey, Duration.ofHours(1));
        } catch (Exception e) {
            log.error("Failed to track rate limit violation", e);
        }
        
        return response.writeWith(Mono.just(buffer));
    }
    
    private String extractToken(ServerHttpRequest request) {
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }
    
    private String getClientIp(ServerHttpRequest request) {
        String xForwardedFor = request.getHeaders().getFirst("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeaders().getFirst("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddress() != null ? 
            request.getRemoteAddress().getAddress().getHostAddress() : "unknown";
    }
}