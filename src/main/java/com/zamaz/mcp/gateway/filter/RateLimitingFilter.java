package com.zamaz.mcp.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zamaz.mcp.security.audit.SecurityAuditLogger;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Rate limiting filter to prevent API abuse and DDoS attacks.
 * Implements sliding window algorithm with Redis.
 */
@Component
@Order(1)
@RequiredArgsConstructor
@Slf4j
public class RateLimitingFilter extends OncePerRequestFilter {

    private final RedisTemplate<String, String> redisTemplate;
    private final SecurityAuditLogger auditLogger;
    private final ObjectMapper objectMapper;

    @Value("${rate-limit.enabled:true}")
    private boolean rateLimitEnabled;

    @Value("${rate-limit.requests-per-minute:60}")
    private int requestsPerMinute;

    @Value("${rate-limit.requests-per-hour:1000}")
    private int requestsPerHour;

    @Value("${rate-limit.burst-capacity:10}")
    private int burstCapacity;

    @Value("${rate-limit.authenticated-multiplier:2}")
    private int authenticatedMultiplier;

    private static final String RATE_LIMIT_PREFIX = "rate_limit:";
    private static final String BURST_PREFIX = "burst:";
    private static final String BLACKLIST_PREFIX = "blacklist:";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        if (!rateLimitEnabled || isWhitelisted(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String clientId = getClientIdentifier(request);
        String path = request.getRequestURI();
        
        // Check if client is blacklisted
        if (isBlacklisted(clientId)) {
            rejectRequest(response, "Client is blacklisted", HttpStatus.FORBIDDEN);
            auditLogger.logSecurityViolation("BLACKLISTED_CLIENT_ACCESS", 
                Map.of("clientId", clientId, "path", path));
            return;
        }

        // Get rate limits based on authentication status
        RateLimits limits = getRateLimits(request);
        
        // Check rate limits
        if (!checkRateLimit(clientId, limits)) {
            // Auto-blacklist if excessive violations
            incrementViolations(clientId);
            
            rejectRequest(response, "Rate limit exceeded", HttpStatus.TOO_MANY_REQUESTS);
            auditLogger.logApiRateLimitExceeded(path, limits.perMinute, 
                getCurrentRequestCount(clientId, Duration.ofMinutes(1)));
            return;
        }

        // Check burst protection
        if (!checkBurstLimit(clientId)) {
            rejectRequest(response, "Burst limit exceeded", HttpStatus.TOO_MANY_REQUESTS);
            auditLogger.logSuspiciousActivity("BURST_LIMIT_EXCEEDED", 
                Map.of("clientId", clientId, "path", path));
            return;
        }

        // Add rate limit headers
        addRateLimitHeaders(response, clientId, limits);
        
        filterChain.doFilter(request, response);
    }

    /**
     * Get client identifier for rate limiting.
     */
    private String getClientIdentifier(HttpServletRequest request) {
        // Priority: User ID > API Key > IP Address
        String userId = extractUserId(request);
        if (userId != null) {
            return "user:" + userId;
        }

        String apiKey = request.getHeader("X-API-Key");
        if (apiKey != null) {
            return "api:" + apiKey.substring(0, Math.min(apiKey.length(), 8));
        }

        return "ip:" + getClientIp(request);
    }

    /**
     * Extract user ID from JWT token if present.
     */
    private String extractUserId(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            try {
                // This should use JwtService to extract user ID
                // For now, return null to use IP-based limiting
                return null;
            } catch (Exception e) {
                log.debug("Failed to extract user ID from token", e);
            }
        }
        return null;
    }

    /**
     * Get client IP address.
     */
    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }

    /**
     * Check if request is whitelisted.
     */
    private boolean isWhitelisted(HttpServletRequest request) {
        String path = request.getRequestURI();
        
        // Whitelist health checks and static resources
        return path.startsWith("/actuator/health") ||
               path.startsWith("/api/v1/health") ||
               path.startsWith("/swagger-ui") ||
               path.startsWith("/v3/api-docs") ||
               path.endsWith(".js") ||
               path.endsWith(".css") ||
               path.endsWith(".ico");
    }

    /**
     * Check if client is blacklisted.
     */
    private boolean isBlacklisted(String clientId) {
        String key = BLACKLIST_PREFIX + clientId;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    /**
     * Get rate limits based on authentication status.
     */
    private RateLimits getRateLimits(HttpServletRequest request) {
        boolean isAuthenticated = request.getHeader("Authorization") != null;
        
        int perMinute = requestsPerMinute;
        int perHour = requestsPerHour;
        
        if (isAuthenticated) {
            perMinute *= authenticatedMultiplier;
            perHour *= authenticatedMultiplier;
        }
        
        // Special limits for specific endpoints
        String path = request.getRequestURI();
        if (path.startsWith("/api/v1/auth/login") || path.startsWith("/api/v1/auth/register")) {
            perMinute = Math.min(perMinute, 5); // Stricter limits for auth endpoints
            perHour = Math.min(perHour, 20);
        }
        
        return new RateLimits(perMinute, perHour);
    }

    /**
     * Check rate limit using sliding window algorithm.
     */
    private boolean checkRateLimit(String clientId, RateLimits limits) {
        long currentTime = System.currentTimeMillis();
        
        // Check minute limit
        if (!checkSlidingWindow(clientId + ":minute", currentTime, Duration.ofMinutes(1), limits.perMinute)) {
            return false;
        }
        
        // Check hour limit
        if (!checkSlidingWindow(clientId + ":hour", currentTime, Duration.ofHours(1), limits.perHour)) {
            return false;
        }
        
        return true;
    }

    /**
     * Check sliding window rate limit.
     */
    private boolean checkSlidingWindow(String key, long currentTime, Duration window, int limit) {
        String redisKey = RATE_LIMIT_PREFIX + key;
        long windowStart = currentTime - window.toMillis();
        
        // Remove old entries
        redisTemplate.opsForZSet().removeRangeByScore(redisKey, 0, windowStart);
        
        // Count requests in window
        Long count = redisTemplate.opsForZSet().count(redisKey, windowStart, currentTime);
        if (count == null) {
            count = 0L;
        }
        
        // Check limit
        if (count >= limit) {
            return false;
        }
        
        // Add current request
        redisTemplate.opsForZSet().add(redisKey, String.valueOf(currentTime), currentTime);
        redisTemplate.expire(redisKey, window.toMillis(), TimeUnit.MILLISECONDS);
        
        return true;
    }

    /**
     * Check burst limit to prevent sudden spikes.
     */
    private boolean checkBurstLimit(String clientId) {
        String key = BURST_PREFIX + clientId;
        Long count = redisTemplate.opsForValue().increment(key);
        
        if (count == 1) {
            redisTemplate.expire(key, 1, TimeUnit.SECONDS);
        }
        
        return count <= burstCapacity;
    }

    /**
     * Get current request count for time window.
     */
    private int getCurrentRequestCount(String clientId, Duration window) {
        String redisKey = RATE_LIMIT_PREFIX + clientId + ":" + 
            (window.equals(Duration.ofMinutes(1)) ? "minute" : "hour");
        
        long currentTime = System.currentTimeMillis();
        long windowStart = currentTime - window.toMillis();
        
        Long count = redisTemplate.opsForZSet().count(redisKey, windowStart, currentTime);
        return count != null ? count.intValue() : 0;
    }

    /**
     * Increment violation count and auto-blacklist if necessary.
     */
    private void incrementViolations(String clientId) {
        String key = "violations:" + clientId;
        Long violations = redisTemplate.opsForValue().increment(key);
        
        if (violations == 1) {
            redisTemplate.expire(key, 1, TimeUnit.HOURS);
        }
        
        // Auto-blacklist after 10 violations in an hour
        if (violations >= 10) {
            String blacklistKey = BLACKLIST_PREFIX + clientId;
            redisTemplate.opsForValue().set(blacklistKey, "true", 24, TimeUnit.HOURS);
            
            log.warn("Client {} blacklisted due to excessive rate limit violations", clientId);
            auditLogger.logSecurityViolation("AUTO_BLACKLIST", 
                Map.of("clientId", clientId, "violations", violations));
        }
    }

    /**
     * Add rate limit headers to response.
     */
    private void addRateLimitHeaders(HttpServletResponse response, String clientId, RateLimits limits) {
        int remaining = limits.perMinute - getCurrentRequestCount(clientId, Duration.ofMinutes(1));
        
        response.setHeader("X-RateLimit-Limit", String.valueOf(limits.perMinute));
        response.setHeader("X-RateLimit-Remaining", String.valueOf(Math.max(0, remaining)));
        response.setHeader("X-RateLimit-Reset", String.valueOf(System.currentTimeMillis() + 60000));
    }

    /**
     * Reject request with rate limit error.
     */
    private void rejectRequest(HttpServletResponse response, String message, HttpStatus status) 
            throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        
        Map<String, Object> error = new HashMap<>();
        error.put("error", status.getReasonPhrase());
        error.put("message", message);
        error.put("timestamp", System.currentTimeMillis());
        
        response.getWriter().write(objectMapper.writeValueAsString(error));
    }

    /**
     * Rate limit configuration.
     */
    private static class RateLimits {
        final int perMinute;
        final int perHour;
        
        RateLimits(int perMinute, int perHour) {
            this.perMinute = perMinute;
            this.perHour = perHour;
        }
    }
}