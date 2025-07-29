package com.zamaz.mcp.gateway.monitoring;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Collects and publishes security-related metrics for monitoring and alerting.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class SecurityMetricsCollector {

    private final MeterRegistry meterRegistry;
    private final RedisTemplate<String, Object> redisTemplate;
    
    // Metric counters
    private final Counter authenticationAttempts;
    private final Counter authenticationFailures;
    private final Counter authorizationDenials;
    private final Counter rateLimitViolations;
    private final Counter ddosBlocks;
    private final Counter circuitBreakerOpenings;
    private final Counter suspiciousActivityDetections;
    
    // Metric gauges
    private final AtomicLong activeUsers = new AtomicLong(0);
    private final AtomicLong blockedIPs = new AtomicLong(0);
    private final AtomicLong activeSessions = new AtomicLong(0);
    
    // Timing metrics
    private final Timer authenticationDuration;
    private final Timer authorizationDuration;
    
    // Threat tracking
    private final ConcurrentHashMap<String, AtomicLong> threatCounters = new ConcurrentHashMap<>();
    
    public SecurityMetricsCollector(MeterRegistry meterRegistry, RedisTemplate<String, Object> redisTemplate) {
        this.meterRegistry = meterRegistry;
        this.redisTemplate = redisTemplate;
        
        // Initialize counters
        this.authenticationAttempts = Counter.builder("security.authentication.attempts")
                .description("Total authentication attempts")
                .register(meterRegistry);
                
        this.authenticationFailures = Counter.builder("security.authentication.failures")
                .description("Failed authentication attempts")
                .register(meterRegistry);
                
        this.authorizationDenials = Counter.builder("security.authorization.denials")
                .description("Authorization denials")
                .register(meterRegistry);
                
        this.rateLimitViolations = Counter.builder("security.rate_limit.violations")
                .description("Rate limit violations")
                .register(meterRegistry);
                
        this.ddosBlocks = Counter.builder("security.ddos.blocks")
                .description("DDoS protection blocks")
                .register(meterRegistry);
                
        this.circuitBreakerOpenings = Counter.builder("security.circuit_breaker.openings")
                .description("Circuit breaker openings")
                .register(meterRegistry);
                
        this.suspiciousActivityDetections = Counter.builder("security.suspicious_activity.detections")
                .description("Suspicious activity detections")
                .register(meterRegistry);
        
        // Initialize timers
        this.authenticationDuration = Timer.builder("security.authentication.duration")
                .description("Authentication processing time")
                .register(meterRegistry);
                
        this.authorizationDuration = Timer.builder("security.authorization.duration")
                .description("Authorization processing time")
                .register(meterRegistry);
        
        // Initialize gauges
        Gauge.builder("security.users.active")
                .description("Number of active users")
                .register(meterRegistry, this, SecurityMetricsCollector::getActiveUsers);
                
        Gauge.builder("security.ips.blocked")
                .description("Number of blocked IP addresses")
                .register(meterRegistry, this, SecurityMetricsCollector::getBlockedIPs);
                
        Gauge.builder("security.sessions.active")
                .description("Number of active sessions")
                .register(meterRegistry, this, SecurityMetricsCollector::getActiveSessions);
    }
    
    // Authentication metrics
    public void recordAuthenticationAttempt() {
        authenticationAttempts.increment();
        log.debug("Authentication attempt recorded");
    }
    
    public void recordAuthenticationFailure(String reason) {
        authenticationFailures.increment();
        meterRegistry.counter("security.authentication.failures", "reason", reason).increment();
        log.warn("Authentication failure recorded: {}", reason);
    }
    
    public void recordAuthenticationSuccess(Duration duration) {
        authenticationDuration.record(duration);
        log.debug("Authentication success recorded in {}ms", duration.toMillis());
    }
    
    // Authorization metrics
    public void recordAuthorizationDenial(String resource, String permission) {
        authorizationDenials.increment();
        meterRegistry.counter("security.authorization.denials", 
                "resource", resource, "permission", permission).increment();
        log.warn("Authorization denial recorded: {} - {}", resource, permission);
    }
    
    public void recordAuthorizationSuccess(Duration duration) {
        authorizationDuration.record(duration);
        log.debug("Authorization success recorded in {}ms", duration.toMillis());
    }
    
    // Rate limiting metrics
    public void recordRateLimitViolation(String clientId, String endpoint) {
        rateLimitViolations.increment();
        meterRegistry.counter("security.rate_limit.violations", 
                "client", clientId, "endpoint", endpoint).increment();
        log.warn("Rate limit violation recorded: {} - {}", clientId, endpoint);
    }
    
    // DDoS protection metrics
    public void recordDDoSBlock(String clientId, String reason) {
        ddosBlocks.increment();
        meterRegistry.counter("security.ddos.blocks", "reason", reason).increment();
        updateBlockedIPs();
        log.warn("DDoS block recorded: {} - {}", clientId, reason);
    }
    
    // Circuit breaker metrics
    public void recordCircuitBreakerOpening(String service) {
        circuitBreakerOpenings.increment();
        meterRegistry.counter("security.circuit_breaker.openings", "service", service).increment();
        log.warn("Circuit breaker opening recorded: {}", service);
    }
    
    // Suspicious activity metrics
    public void recordSuspiciousActivity(String type, String clientId, String details) {
        suspiciousActivityDetections.increment();
        meterRegistry.counter("security.suspicious_activity.detections", "type", type).increment();
        
        // Track threat patterns
        String threatKey = type + ":" + clientId;
        threatCounters.computeIfAbsent(threatKey, k -> new AtomicLong(0)).incrementAndGet();
        
        log.warn("Suspicious activity recorded: {} - {} - {}", type, clientId, details);
    }
    
    // Session metrics
    public void recordUserLogin(String userId) {
        activeUsers.incrementAndGet();
        activeSessions.incrementAndGet();
        updateActiveUserCount();
        log.debug("User login recorded: {}", userId);
    }
    
    public void recordUserLogout(String userId) {
        activeUsers.decrementAndGet();
        activeSessions.decrementAndGet();
        updateActiveUserCount();
        log.debug("User logout recorded: {}", userId);
    }
    
    public void recordSessionExpiry(String sessionId) {
        activeSessions.decrementAndGet();
        log.debug("Session expiry recorded: {}", sessionId);
    }
    
    // Threat analysis
    public long getThreatCount(String threatType, String clientId) {
        String threatKey = threatType + ":" + clientId;
        AtomicLong counter = threatCounters.get(threatKey);
        return counter != null ? counter.get() : 0;
    }
    
    public void resetThreatCount(String threatType, String clientId) {
        String threatKey = threatType + ":" + clientId;
        threatCounters.remove(threatKey);
        log.debug("Threat count reset: {}", threatKey);
    }
    
    // Update methods for gauges
    private double getActiveUsers() {
        return activeUsers.get();
    }
    
    private double getBlockedIPs() {
        return blockedIPs.get();
    }
    
    private double getActiveSessions() {
        return activeSessions.get();
    }
    
    private void updateActiveUserCount() {
        try {
            Long count = redisTemplate.opsForSet().size("active_users");
            activeUsers.set(count != null ? count : 0);
        } catch (Exception e) {
            log.error("Failed to update active user count from Redis", e);
        }
    }
    
    private void updateBlockedIPs() {
        try {
            Long count = redisTemplate.opsForSet().size("blocked_ips");
            blockedIPs.set(count != null ? count : 0);
        } catch (Exception e) {
            log.error("Failed to update blocked IP count from Redis", e);
        }
    }
    
    // Security health indicators
    public boolean isSecurityHealthy() {
        long recentFailures = authenticationFailures.count();
        long recentViolations = rateLimitViolations.count();
        long recentBlocks = ddosBlocks.count();
        
        // Define thresholds for unhealthy state
        return recentFailures < 100 && recentViolations < 50 && recentBlocks < 10;
    }
    
    public SecurityHealthStatus getSecurityHealthStatus() {
        return SecurityHealthStatus.builder()
                .authenticationFailures(authenticationFailures.count())
                .authorizationDenials(authorizationDenials.count())
                .rateLimitViolations(rateLimitViolations.count())
                .ddosBlocks(ddosBlocks.count())
                .circuitBreakerOpenings(circuitBreakerOpenings.count())
                .suspiciousActivities(suspiciousActivityDetections.count())
                .activeUsers(activeUsers.get())
                .blockedIPs(blockedIPs.get())
                .activeSessions(activeSessions.get())
                .isHealthy(isSecurityHealthy())
                .build();
    }
    
    @lombok.Data
    @lombok.Builder
    public static class SecurityHealthStatus {
        private double authenticationFailures;
        private double authorizationDenials;
        private double rateLimitViolations;
        private double ddosBlocks;
        private double circuitBreakerOpenings;
        private double suspiciousActivities;
        private long activeUsers;
        private long blockedIPs;
        private long activeSessions;
        private boolean isHealthy;
    }
}