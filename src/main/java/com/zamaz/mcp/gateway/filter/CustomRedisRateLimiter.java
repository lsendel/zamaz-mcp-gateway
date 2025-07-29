package com.zamaz.mcp.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.ratelimit.AbstractRateLimiter;
import org.springframework.cloud.gateway.filter.ratelimit.RateLimiter;
import org.springframework.cloud.gateway.support.ConfigurationService;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.validation.Validator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Custom Redis rate limiter with organization-based rate limiting
 */
@Slf4j
public class CustomRedisRateLimiter extends AbstractRateLimiter<CustomRedisRateLimiter.Config> {
    
    public static final String CONFIGURATION_PROPERTY_NAME = "custom-redis-rate-limiter";
    public static final String REMAINING_HEADER = "X-RateLimit-Remaining";
    public static final String REPLENISH_RATE_HEADER = "X-RateLimit-Replenish-Rate";
    public static final String BURST_CAPACITY_HEADER = "X-RateLimit-Burst-Capacity";
    public static final String REQUESTED_TOKENS_HEADER = "X-RateLimit-Requested-Tokens";
    
    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final RedisScript<List<Long>> script;
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    
    // Organization-specific rate limits
    private final Map<String, Config> organizationConfigs = new HashMap<>();
    
    public CustomRedisRateLimiter(ReactiveRedisTemplate<String, String> redisTemplate,
                                  RedisScript<List<Long>> script) {
        super(Config.class, CONFIGURATION_PROPERTY_NAME, (ConfigurationService) null);
        this.redisTemplate = redisTemplate;
        this.script = script;
        initialized.compareAndSet(false, true);
    }
    
    @Override
    public Mono<Response> isAllowed(String routeId, String id) {
        if (!this.initialized.get()) {
            throw new IllegalStateException("RedisRateLimiter is not initialized");
        }
        
        Config routeConfig = loadConfiguration(routeId);
        
        // Extract organization ID from the key
        String orgId = extractOrganizationId(id);
        Config config = organizationConfigs.getOrDefault(orgId, routeConfig);
        
        // Rate limiter key
        String key = "rate_limiter." + id;
        
        // How many requests per second do you want a user to be allowed to do?
        int replenishRate = config.getReplenishRate();
        
        // How much bursting do you want to allow?
        int burstCapacity = config.getBurstCapacity();
        
        // How many tokens are requested per request?
        int requestedTokens = config.getRequestedTokens();
        
        try {
            List<String> keys = getKeys(key);
            List<String> scriptArgs = Arrays.asList(
                replenishRate + "",
                burstCapacity + "",
                Instant.now().getEpochSecond() + "",
                requestedTokens + ""
            );
            
            Flux<List<Long>> flux = this.redisTemplate.execute(this.script, keys, scriptArgs);
            
            return flux.onErrorResume(throwable -> {
                log.error("Error during rate limit check", throwable);
                return Flux.just(Arrays.asList(1L, -1L));
            }).reduce(new ArrayList<Long>(), (longs, l) -> {
                longs.addAll(l);
                return longs;
            }).map(results -> {
                boolean allowed = results.get(0) == 1L;
                Long tokensLeft = results.get(1);
                
                Response response = new Response(allowed, getHeaders(config, tokensLeft));
                
                log.debug("Rate limit response for {}: allowed={}, tokensLeft={}", 
                    id, allowed, tokensLeft);
                
                return response;
            });
        } catch (Exception e) {
            log.error("Error during rate limit processing", e);
            return Mono.just(new Response(true, getHeaders(config, -1L)));
        }
    }
    
    private String extractOrganizationId(String key) {
        // Key format: "org:orgId:userId" or "org:orgId"
        if (key.startsWith("org:")) {
            String[] parts = key.split(":");
            if (parts.length >= 2) {
                return parts[1];
            }
        }
        return "default";
    }
    
    private Config loadConfiguration(String routeId) {
        Config config = getConfig().getOrDefault(routeId, defaultConfig);
        if (config == null) {
            config = defaultConfig;
        }
        return config;
    }
    
    private List<String> getKeys(String id) {
        String prefix = "request_rate_limiter.{" + id;
        String tokenKey = prefix + "}.tokens";
        String timestampKey = prefix + "}.timestamp";
        return Arrays.asList(tokenKey, timestampKey);
    }
    
    private Map<String, String> getHeaders(Config config, Long tokensLeft) {
        Map<String, String> headers = new HashMap<>();
        if (config != null) {
            headers.put(REMAINING_HEADER, tokensLeft.toString());
            headers.put(REPLENISH_RATE_HEADER, String.valueOf(config.getReplenishRate()));
            headers.put(BURST_CAPACITY_HEADER, String.valueOf(config.getBurstCapacity()));
            headers.put(REQUESTED_TOKENS_HEADER, String.valueOf(config.getRequestedTokens()));
        }
        return headers;
    }
    
    /**
     * Set organization-specific rate limit configuration
     */
    public void setOrganizationConfig(String organizationId, Config config) {
        organizationConfigs.put(organizationId, config);
    }
    
    private Config defaultConfig = new Config()
        .setReplenishRate(50)
        .setBurstCapacity(100)
        .setRequestedTokens(1);
    
    @Override
    public void setValidator(Validator validator) {
        // No-op
    }
    
    @Override
    public Validator getValidator() {
        return null;
    }
    
    public static class Config {
        private int replenishRate = 50;
        private int burstCapacity = 100;
        private int requestedTokens = 1;
        
        public int getReplenishRate() {
            return replenishRate;
        }
        
        public Config setReplenishRate(int replenishRate) {
            this.replenishRate = replenishRate;
            return this;
        }
        
        public int getBurstCapacity() {
            return burstCapacity;
        }
        
        public Config setBurstCapacity(int burstCapacity) {
            this.burstCapacity = burstCapacity;
            return this;
        }
        
        public int getRequestedTokens() {
            return requestedTokens;
        }
        
        public Config setRequestedTokens(int requestedTokens) {
            this.requestedTokens = requestedTokens;
            return this;
        }
        
        @Override
        public String toString() {
            return "Config{" +
                "replenishRate=" + replenishRate +
                ", burstCapacity=" + burstCapacity +
                ", requestedTokens=" + requestedTokens +
                '}';
        }
    }
}