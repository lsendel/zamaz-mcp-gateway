package com.zamaz.mcp.gateway.filter;

import com.zamaz.mcp.security.audit.SecurityAuditService;
import com.zamaz.mcp.security.entity.SecurityAuditLog.SecurityEventType;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.Refill;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.grid.jcache.JCacheProxyManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.cache.Cache;
import javax.cache.CacheManager;
import javax.cache.Caching;
import javax.cache.configuration.MutableConfiguration;
import javax.cache.expiry.CreatedExpiryPolicy;
import javax.cache.expiry.Duration;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Gateway filter for rate limiting to prevent DDoS attacks.
 * Uses Redis-backed token bucket algorithm for distributed rate limiting.
 */
@Component
public class RateLimitingGatewayFilterFactory 
    extends AbstractGatewayFilterFactory<RateLimitingGatewayFilterFactory.Config> {
    
    private static final Logger logger = LoggerFactory.getLogger(RateLimitingGatewayFilterFactory.class);
    
    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final SecurityAuditService auditService;
    private final ProxyManager<String> buckets;
    private final Map<String, Instant> blacklist = new ConcurrentHashMap<>();
    
    public RateLimitingGatewayFilterFactory(
            ReactiveRedisTemplate<String, String> redisTemplate,
            SecurityAuditService auditService) {
        super(Config.class);
        this.redisTemplate = redisTemplate;
        this.auditService = auditService;
        
        // Initialize distributed cache for rate limiting
        CacheManager cacheManager = Caching.getCachingProvider().getCacheManager();
        MutableConfiguration<String, byte[]> config = new MutableConfiguration<>();
        config.setExpiryPolicyFactory(CreatedExpiryPolicy.factoryOf(Duration.ONE_HOUR));
        
        Cache<String, byte[]> cache = cacheManager.createCache("rate-limit-buckets", config);
        this.buckets = new JCacheProxyManager<>(cache);
    }
    
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String key = resolveKey(exchange, config);
            
            // Check if key is blacklisted
            if (isBlacklisted(key)) {
                return handleRateLimitExceeded(exchange, key, "Temporarily blocked due to excessive requests");
            }
            
            // Get or create bucket for the key
            BucketConfiguration bucketConfig = createBucketConfiguration(config);
            Bucket bucket = buckets.builder().build(key, bucketConfig);
            
            // Try to consume a token
            if (bucket.tryConsume(1)) {
                // Add rate limit headers
                ServerHttpResponse response = exchange.getResponse();
                response.getHeaders().add("X-RateLimit-Limit", String.valueOf(config.getReplenishRate()));
                response.getHeaders().add("X-RateLimit-Remaining", 
                    String.valueOf(bucket.getAvailableTokens()));
                response.getHeaders().add("X-RateLimit-Retry-After", 
                    String.valueOf(bucket.estimateAbilityToConsume(1).getRoundedSecondsToWait()));
                
                return chain.filter(exchange);
            } else {
                // Rate limit exceeded
                return handleRateLimitExceeded(exchange, key, "Rate limit exceeded");
            }
        };
    }
    
    private String resolveKey(ServerWebExchange exchange, Config config) {
        switch (config.getKeyResolver()) {
            case IP:
                return getClientIP(exchange);
            case USER:
                return ReactiveSecurityContextHolder.getContext()
                    .map(ctx -> ctx.getAuthentication().getName())
                    .defaultIfEmpty("anonymous")
                    .block();
            case API_KEY:
                return exchange.getRequest().getHeaders().getFirst("X-API-Key");
            case PATH:
                return exchange.getRequest().getPath().value();
            case IP_AND_PATH:
                return getClientIP(exchange) + ":" + exchange.getRequest().getPath().value();
            default:
                return getClientIP(exchange);
        }
    }
    
    private String getClientIP(ServerWebExchange exchange) {
        HttpHeaders headers = exchange.getRequest().getHeaders();
        
        // Check X-Forwarded-For header
        String xForwardedFor = headers.getFirst("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        // Check X-Real-IP header
        String xRealIP = headers.getFirst("X-Real-IP");
        if (xRealIP != null && !xRealIP.isEmpty()) {
            return xRealIP;
        }
        
        // Fall back to remote address
        return exchange.getRequest().getRemoteAddress() != null 
            ? exchange.getRequest().getRemoteAddress().getAddress().getHostAddress()
            : "unknown";
    }
    
    private BucketConfiguration createBucketConfiguration(Config config) {
        Bandwidth limit = Bandwidth.classic(
            config.getReplenishRate(),
            Refill.intervally(config.getReplenishRate(), 
                java.time.Duration.ofSeconds(config.getDuration()))
        );
        
        return BucketConfiguration.builder()
            .addLimit(limit)
            .build();
    }
    
    private boolean isBlacklisted(String key) {
        Instant blacklistExpiry = blacklist.get(key);
        if (blacklistExpiry == null) {
            return false;
        }
        
        if (Instant.now().isAfter(blacklistExpiry)) {
            blacklist.remove(key);
            return false;
        }
        
        return true;
    }
    
    private void addToBlacklist(String key, long durationMinutes) {
        Instant expiry = Instant.now().plusSeconds(durationMinutes * 60);
        blacklist.put(key, expiry);
        
        // Also store in Redis for distributed blacklist
        redisTemplate.opsForValue()
            .set("blacklist:" + key, expiry.toString(), 
                java.time.Duration.ofMinutes(durationMinutes))
            .subscribe();
    }
    
    private Mono<Void> handleRateLimitExceeded(ServerWebExchange exchange, String key, String reason) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.getHeaders().add("Retry-After", "60");
        
        // Audit the rate limit violation
        auditService.logSecurityEvent(
            SecurityEventType.ACCESS_DENIED,
            key,
            "Rate limit exceeded",
            Map.of(
                "path", exchange.getRequest().getPath().value(),
                "method", exchange.getRequest().getMethod().toString(),
                "reason", reason
            )
        );
        
        // Check if this key should be blacklisted
        checkForBlacklisting(key);
        
        String errorBody = String.format(
            "{\"error\": \"Too Many Requests\", \"message\": \"%s\", \"retryAfter\": 60}",
            reason
        );
        
        DataBuffer buffer = response.bufferFactory().wrap(errorBody.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Flux.just(buffer));
    }
    
    private void checkForBlacklisting(String key) {
        String violationKey = "violations:" + key;
        
        redisTemplate.opsForValue()
            .increment(violationKey)
            .flatMap(count -> {
                if (count >= 10) { // 10 violations in the time window
                    addToBlacklist(key, 15); // Blacklist for 15 minutes
                    logger.warn("Key {} blacklisted due to excessive rate limit violations", key);
                    
                    // Reset violation counter
                    return redisTemplate.delete(violationKey);
                } else {
                    // Set expiry on violation counter
                    return redisTemplate.expire(violationKey, 
                        java.time.Duration.ofMinutes(5));
                }
            })
            .subscribe();
    }
    
    public static class Config {
        private int replenishRate = 10; // tokens per duration
        private int burstCapacity = 20; // maximum tokens
        private int duration = 1; // duration in seconds
        private KeyResolver keyResolver = KeyResolver.IP;
        private boolean enableBlacklisting = true;
        private int blacklistThreshold = 10;
        private int blacklistDurationMinutes = 15;
        
        public enum KeyResolver {
            IP,
            USER,
            API_KEY,
            PATH,
            IP_AND_PATH
        }
        
        // Getters and setters
        public int getReplenishRate() { return replenishRate; }
        public void setReplenishRate(int replenishRate) { this.replenishRate = replenishRate; }
        
        public int getBurstCapacity() { return burstCapacity; }
        public void setBurstCapacity(int burstCapacity) { this.burstCapacity = burstCapacity; }
        
        public int getDuration() { return duration; }
        public void setDuration(int duration) { this.duration = duration; }
        
        public KeyResolver getKeyResolver() { return keyResolver; }
        public void setKeyResolver(KeyResolver keyResolver) { this.keyResolver = keyResolver; }
        
        public boolean isEnableBlacklisting() { return enableBlacklisting; }
        public void setEnableBlacklisting(boolean enableBlacklisting) { 
            this.enableBlacklisting = enableBlacklisting; 
        }
        
        public int getBlacklistThreshold() { return blacklistThreshold; }
        public void setBlacklistThreshold(int blacklistThreshold) { 
            this.blacklistThreshold = blacklistThreshold; 
        }
        
        public int getBlacklistDurationMinutes() { return blacklistDurationMinutes; }
        public void setBlacklistDurationMinutes(int blacklistDurationMinutes) { 
            this.blacklistDurationMinutes = blacklistDurationMinutes; 
        }
    }
}