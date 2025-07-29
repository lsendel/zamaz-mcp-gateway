package com.zamaz.mcp.gateway.monitoring;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Continuous security monitoring service that analyzes security metrics and triggers alerts.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SecurityMonitoringService {

    private final SecurityMetricsCollector metricsCollector;
    private final SecurityAlertManager alertManager;
    private final RedisTemplate<String, Object> redisTemplate;
    
    // Monitoring thresholds
    private static final int AUTH_FAILURE_THRESHOLD = 10;
    private static final int RATE_LIMIT_THRESHOLD = 20;
    private static final int DDOS_THRESHOLD = 5;
    private static final int SUSPICIOUS_ACTIVITY_THRESHOLD = 15;
    private static final Duration MONITORING_WINDOW = Duration.ofMinutes(5);
    
    /**
     * Monitor authentication failures every minute
     */
    @Scheduled(fixedRate = 60000) // Every minute
    public void monitorAuthenticationFailures() {
        try {
            // Get recent authentication failure counts per IP
            Set<String> failedIPs = redisTemplate.opsForSet().members("auth_failures:recent");
            
            if (failedIPs != null) {
                for (String ip : failedIPs) {
                    String key = "auth_failures:" + ip;
                    String countStr = (String) redisTemplate.opsForValue().get(key);
                    
                    if (countStr != null) {
                        int count = Integer.parseInt(countStr);
                        if (count >= AUTH_FAILURE_THRESHOLD) {
                            alertManager.alertAuthenticationFailures(ip, count, MONITORING_WINDOW.toString());
                            
                            // Auto-block IP after excessive failures
                            if (count >= AUTH_FAILURE_THRESHOLD * 2) {
                                blockMaliciousIP(ip, "Excessive authentication failures");
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error monitoring authentication failures", e);
        }
    }
    
    /**
     * Monitor rate limiting violations every 2 minutes
     */
    @Scheduled(fixedRate = 120000) // Every 2 minutes
    public void monitorRateLimitViolations() {
        try {
            Set<String> violatingClients = redisTemplate.opsForSet().members("rate_limit_violations:recent");
            
            if (violatingClients != null) {
                for (String clientId : violatingClients) {
                    String key = "rate_limit_violations:" + clientId;
                    String countStr = (String) redisTemplate.opsForValue().get(key);
                    
                    if (countStr != null) {
                        int count = Integer.parseInt(countStr);
                        if (count >= RATE_LIMIT_THRESHOLD) {
                            Map<String, String> details = new HashMap<>();
                            details.put("clientId", clientId);
                            details.put("violationCount", String.valueOf(count));
                            details.put("timeWindow", MONITORING_WINDOW.toString());
                            
                            alertManager.sendMediumAlert(
                                "Rate Limit Violations Detected",
                                String.format("Client %s has %d rate limit violations", clientId, count),
                                details
                            );
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error monitoring rate limit violations", e);
        }
    }
    
    /**
     * Monitor DDoS attacks every 30 seconds
     */
    @Scheduled(fixedRate = 30000) // Every 30 seconds
    public void monitorDDoSAttacks() {
        try {
            Set<String> suspiciousIPs = redisTemplate.opsForSet().members("ddos_suspects");
            
            if (suspiciousIPs != null) {
                for (String ip : suspiciousIPs) {
                    String key = "ddos_score:" + ip;
                    String scoreStr = (String) redisTemplate.opsForValue().get(key);
                    
                    if (scoreStr != null) {
                        int score = Integer.parseInt(scoreStr);
                        if (score >= DDOS_THRESHOLD) {
                            String requestCountKey = "request_count:" + ip;
                            String requestCountStr = (String) redisTemplate.opsForValue().get(requestCountKey);
                            int requestCount = requestCountStr != null ? Integer.parseInt(requestCountStr) : 0;
                            
                            alertManager.alertDDoSAttack("Connection Flood", ip, requestCount, "30 seconds");
                            blockMaliciousIP(ip, "DDoS attack pattern detected");
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error monitoring DDoS attacks", e);
        }
    }
    
    /**
     * Monitor suspicious activities every 3 minutes
     */
    @Scheduled(fixedRate = 180000) // Every 3 minutes
    public void monitorSuspiciousActivities() {
        try {
            // Monitor SQL injection attempts
            monitorSQLInjectionAttempts();
            
            // Monitor XSS attempts
            monitorXSSAttempts();
            
            // Monitor path traversal attempts
            monitorPathTraversalAttempts();
            
            // Monitor scanner tools
            monitorScannerTools();
            
        } catch (Exception e) {
            log.error("Error monitoring suspicious activities", e);
        }
    }
    
    /**
     * Monitor circuit breaker states every minute
     */
    @Scheduled(fixedRate = 60000) // Every minute
    public void monitorCircuitBreakers() {
        try {
            Set<String> services = redisTemplate.opsForSet().members("services");
            
            if (services != null) {
                for (String service : services) {
                    String stateKey = "circuit_breaker:" + service + ":state";
                    String state = (String) redisTemplate.opsForValue().get(stateKey);
                    
                    if ("OPEN".equals(state)) {
                        String reasonKey = "circuit_breaker:" + service + ":reason";
                        String reason = (String) redisTemplate.opsForValue().get(reasonKey);
                        
                        alertManager.alertCircuitBreakerOpen(service, reason != null ? reason : "Unknown");
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error monitoring circuit breakers", e);
        }
    }
    
    /**
     * Generate security health report every 5 minutes
     */
    @Scheduled(fixedRate = 300000) // Every 5 minutes
    public void generateSecurityHealthReport() {
        try {
            SecurityMetricsCollector.SecurityHealthStatus status = metricsCollector.getSecurityHealthStatus();
            
            if (!status.isHealthy()) {
                Map<String, String> details = new HashMap<>();
                details.put("authFailures", String.valueOf(status.getAuthenticationFailures()));
                details.put("authDenials", String.valueOf(status.getAuthorizationDenials()));
                details.put("rateLimitViolations", String.valueOf(status.getRateLimitViolations()));
                details.put("ddosBlocks", String.valueOf(status.getDdosBlocks()));
                details.put("circuitBreakerOpenings", String.valueOf(status.getCircuitBreakerOpenings()));
                details.put("suspiciousActivities", String.valueOf(status.getSuspiciousActivities()));
                
                alertManager.sendMediumAlert(
                    "Security Health Degraded",
                    "Overall security health has degraded due to increased security events",
                    details
                );
            }
            
            log.info("Security Health Status: {}", status.isHealthy() ? "HEALTHY" : "DEGRADED");
            log.debug("Security metrics: Auth failures={}, Rate violations={}, DDoS blocks={}, Active users={}",
                    status.getAuthenticationFailures(), status.getRateLimitViolations(),
                    status.getDdosBlocks(), status.getActiveUsers());
                    
        } catch (Exception e) {
            log.error("Error generating security health report", e);
        }
    }
    
    /**
     * Clean up old monitoring data every hour
     */
    @Scheduled(fixedRate = 3600000) // Every hour
    public void cleanupMonitoringData() {
        try {
            // Clean up old authentication failure records
            cleanupRedisKeys("auth_failures:*", TimeUnit.HOURS.toSeconds(2));
            
            // Clean up old rate limit violation records
            cleanupRedisKeys("rate_limit_violations:*", TimeUnit.HOURS.toSeconds(1));
            
            // Clean up old request count records
            cleanupRedisKeys("request_count:*", TimeUnit.MINUTES.toSeconds(30));
            
            // Clean up old DDoS score records
            cleanupRedisKeys("ddos_score:*", TimeUnit.MINUTES.toSeconds(15));
            
            log.debug("Monitoring data cleanup completed");
        } catch (Exception e) {
            log.error("Error cleaning up monitoring data", e);
        }
    }
    
    private void monitorSQLInjectionAttempts() {
        Set<String> suspiciousIPs = redisTemplate.opsForSet().members("sql_injection_attempts");
        if (suspiciousIPs != null) {
            for (String ip : suspiciousIPs) {
                String key = "sql_injection_count:" + ip;
                String countStr = (String) redisTemplate.opsForValue().get(key);
                if (countStr != null && Integer.parseInt(countStr) >= 3) {
                    alertManager.alertSuspiciousActivity("SQL Injection", ip, "Multiple SQL injection attempts detected");
                    blockMaliciousIP(ip, "SQL injection attempts");
                }
            }
        }
    }
    
    private void monitorXSSAttempts() {
        Set<String> suspiciousIPs = redisTemplate.opsForSet().members("xss_attempts");
        if (suspiciousIPs != null) {
            for (String ip : suspiciousIPs) {
                String key = "xss_count:" + ip;
                String countStr = (String) redisTemplate.opsForValue().get(key);
                if (countStr != null && Integer.parseInt(countStr) >= 3) {
                    alertManager.alertSuspiciousActivity("XSS", ip, "Multiple XSS attempts detected");
                    blockMaliciousIP(ip, "XSS attempts");
                }
            }
        }
    }
    
    private void monitorPathTraversalAttempts() {
        Set<String> suspiciousIPs = redisTemplate.opsForSet().members("path_traversal_attempts");
        if (suspiciousIPs != null) {
            for (String ip : suspiciousIPs) {
                String key = "path_traversal_count:" + ip;
                String countStr = (String) redisTemplate.opsForValue().get(key);
                if (countStr != null && Integer.parseInt(countStr) >= 2) {
                    alertManager.alertSuspiciousActivity("Path Traversal", ip, "Path traversal attempts detected");
                    blockMaliciousIP(ip, "Path traversal attempts");
                }
            }
        }
    }
    
    private void monitorScannerTools() {
        Set<String> scannerIPs = redisTemplate.opsForSet().members("scanner_tools");
        if (scannerIPs != null) {
            for (String ip : scannerIPs) {
                alertManager.alertSuspiciousActivity("Scanner Tool", ip, "Known scanner tool user agent detected");
                blockMaliciousIP(ip, "Scanner tool usage");
            }
        }
    }
    
    private void blockMaliciousIP(String ip, String reason) {
        try {
            // Add to blocked IPs set
            redisTemplate.opsForSet().add("blocked_ips", ip);
            
            // Set expiration for auto-unblock (24 hours)
            String blockKey = "blocked:" + ip;
            redisTemplate.opsForValue().set(blockKey, reason, Duration.ofHours(24));
            
            // Record the block
            metricsCollector.recordDDoSBlock(ip, reason);
            
            log.warn("IP {} has been automatically blocked: {}", ip, reason);
        } catch (Exception e) {
            log.error("Failed to block malicious IP: " + ip, e);
        }
    }
    
    private void cleanupRedisKeys(String pattern, long maxAgeSeconds) {
        try {
            Set<String> keys = redisTemplate.keys(pattern);
            if (keys != null) {
                long now = System.currentTimeMillis() / 1000;
                for (String key : keys) {
                    Long ttl = redisTemplate.getExpire(key, TimeUnit.SECONDS);
                    if (ttl != null && ttl > 0 && (now - ttl) > maxAgeSeconds) {
                        redisTemplate.delete(key);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error cleaning up Redis keys with pattern: " + pattern, e);
        }
    }
}