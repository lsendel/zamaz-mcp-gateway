package com.zamaz.mcp.gateway.config;

import com.zamaz.mcp.gateway.filter.CustomRedisRateLimiter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Rate limiter configuration with multiple strategies
 */
@Configuration
public class RateLimiterConfig {
    
    @Value("${rate-limiter.default.replenish-rate:50}")
    private int defaultReplenishRate;
    
    @Value("${rate-limiter.default.burst-capacity:100}")
    private int defaultBurstCapacity;
    
    @Value("${rate-limiter.default.requested-tokens:1}")
    private int defaultRequestedTokens;
    
    /**
     * Default rate limiter
     */
    @Bean
    @Primary
    public RedisRateLimiter defaultRedisRateLimiter() {
        return new RedisRateLimiter(defaultReplenishRate, defaultBurstCapacity, defaultRequestedTokens);
    }
    
    /**
     * Strict rate limiter for expensive operations
     */
    @Bean
    public RedisRateLimiter strictRedisRateLimiter() {
        return new RedisRateLimiter(10, 20, 1); // 10 requests per second, burst of 20
    }
    
    /**
     * Relaxed rate limiter for read operations
     */
    @Bean
    public RedisRateLimiter relaxedRedisRateLimiter() {
        return new RedisRateLimiter(200, 400, 1); // 200 requests per second, burst of 400
    }
    
    /**
     * Custom rate limiter with organization-based limits
     */
    @Bean
    public CustomRedisRateLimiter customRedisRateLimiter(
            ReactiveRedisTemplate<String, String> redisTemplate,
            RedisScript<List<Long>> script) {
        return new CustomRedisRateLimiter(redisTemplate, script);
    }
    
    /**
     * Composite key resolver that combines user and organization
     */
    @Bean
    @Primary
    public KeyResolver compositeKeyResolver() {
        return exchange -> {
            String userId = exchange.getRequest().getHeaders().getFirst("X-User-ID");
            String orgId = exchange.getRequest().getHeaders().getFirst("X-Organization-ID");
            
            if (StringUtils.hasText(userId) && StringUtils.hasText(orgId)) {
                return Mono.just(orgId + ":" + userId);
            } else if (StringUtils.hasText(userId)) {
                return Mono.just("user:" + userId);
            } else if (StringUtils.hasText(orgId)) {
                return Mono.just("org:" + orgId);
            } else {
                // Fall back to IP address
                String ip = exchange.getRequest().getRemoteAddress() != null 
                    ? exchange.getRequest().getRemoteAddress().getAddress().getHostAddress()
                    : "unknown";
                return Mono.just("ip:" + ip);
            }
        };
    }
    
    /**
     * API key resolver for external API access
     */
    @Bean
    public KeyResolver apiKeyResolver() {
        return exchange -> {
            String apiKey = exchange.getRequest().getHeaders().getFirst("X-API-Key");
            return StringUtils.hasText(apiKey) ? Mono.just("api:" + apiKey) : Mono.empty();
        };
    }
    
    /**
     * Path-based key resolver for rate limiting by endpoint
     */
    @Bean
    public KeyResolver pathKeyResolver() {
        return exchange -> {
            String path = exchange.getRequest().getPath().value();
            String method = exchange.getRequest().getMethod().toString();
            return Mono.just(method + ":" + path);
        };
    }
}