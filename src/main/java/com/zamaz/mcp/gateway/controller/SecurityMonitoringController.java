package com.zamaz.mcp.gateway.controller;

import com.zamaz.mcp.gateway.monitoring.SecurityMetricsCollector;
import com.zamaz.mcp.gateway.monitoring.SecurityAlertManager;
import com.zamaz.mcp.security.annotation.RequiresRole;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * REST controller for security monitoring and management operations.
 */
@RestController
@RequestMapping("/api/v1/security/monitoring")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Security Monitoring", description = "Security monitoring and alerting endpoints")
@SecurityRequirement(name = "bearerAuth")
public class SecurityMonitoringController {

    private final SecurityMetricsCollector metricsCollector;
    private final SecurityAlertManager alertManager;
    private final RedisTemplate<String, Object> redisTemplate;

    /**
     * Get overall security health status
     */
    @Operation(summary = "Get security health status", description = "Returns comprehensive security health metrics and status")
    @ApiResponse(responseCode = "200", description = "Security health status retrieved successfully")
    @GetMapping("/health")
    @RequiresRole("ADMIN")
    public ResponseEntity<SecurityMetricsCollector.SecurityHealthStatus> getSecurityHealth() {
        SecurityMetricsCollector.SecurityHealthStatus status = metricsCollector.getSecurityHealthStatus();
        log.debug("Security health status requested: {}", status.isHealthy() ? "HEALTHY" : "DEGRADED");
        return ResponseEntity.ok(status);
    }

    /**
     * Get security metrics summary
     */
    @Operation(summary = "Get security metrics", description = "Returns current security metrics and counters")
    @GetMapping("/metrics")
    @RequiresRole("ADMIN")
    public ResponseEntity<Map<String, Object>> getSecurityMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        SecurityMetricsCollector.SecurityHealthStatus status = metricsCollector.getSecurityHealthStatus();
        metrics.put("authenticationFailures", status.getAuthenticationFailures());
        metrics.put("authorizationDenials", status.getAuthorizationDenials());
        metrics.put("rateLimitViolations", status.getRateLimitViolations());
        metrics.put("ddosBlocks", status.getDdosBlocks());
        metrics.put("circuitBreakerOpenings", status.getCircuitBreakerOpenings());
        metrics.put("suspiciousActivities", status.getSuspiciousActivities());
        metrics.put("activeUsers", status.getActiveUsers());
        metrics.put("blockedIPs", status.getBlockedIPs());
        metrics.put("activeSessions", status.getActiveSessions());
        metrics.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        
        return ResponseEntity.ok(metrics);
    }

    /**
     * Get list of blocked IPs
     */
    @Operation(summary = "Get blocked IPs", description = "Returns list of currently blocked IP addresses")
    @GetMapping("/blocked-ips")
    @RequiresRole("ADMIN")
    public ResponseEntity<Map<String, Object>> getBlockedIPs() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            Set<String> blockedIPs = redisTemplate.opsForSet().members("blocked_ips");
            response.put("blockedIPs", blockedIPs);
            response.put("count", blockedIPs != null ? blockedIPs.size() : 0);
            response.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            
            // Get block reasons for each IP
            if (blockedIPs != null) {
                Map<String, String> blockReasons = new HashMap<>();
                for (String ip : blockedIPs) {
                    String reason = (String) redisTemplate.opsForValue().get("blocked:" + ip);
                    blockReasons.put(ip, reason != null ? reason : "Unknown");
                }
                response.put("blockReasons", blockReasons);
            }
            
        } catch (Exception e) {
            log.error("Error retrieving blocked IPs", e);
            response.put("error", "Failed to retrieve blocked IPs");
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * Manually block an IP address
     */
    @Operation(summary = "Block IP address", description = "Manually block an IP address for security reasons")
    @PostMapping("/block-ip")
    @RequiresRole("ADMIN")
    public ResponseEntity<Map<String, String>> blockIP(
            @RequestParam String ip,
            @RequestParam String reason,
            @RequestParam(defaultValue = "3600") int durationSeconds) {
        
        Map<String, String> response = new HashMap<>();
        
        try {
            // Add to blocked IPs set
            redisTemplate.opsForSet().add("blocked_ips", ip);
            
            // Set reason and expiration
            String blockKey = "blocked:" + ip;
            redisTemplate.opsForValue().set(blockKey, reason, java.time.Duration.ofSeconds(durationSeconds));
            
            // Record the manual block
            metricsCollector.recordDDoSBlock(ip, "MANUAL: " + reason);
            
            response.put("status", "success");
            response.put("message", String.format("IP %s has been blocked for %d seconds", ip, durationSeconds));
            response.put("ip", ip);
            response.put("reason", reason);
            response.put("duration", String.valueOf(durationSeconds));
            
            log.warn("IP {} manually blocked by admin: {}", ip, reason);
            
        } catch (Exception e) {
            log.error("Error blocking IP: " + ip, e);
            response.put("status", "error");
            response.put("message", "Failed to block IP: " + e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * Unblock an IP address
     */
    @Operation(summary = "Unblock IP address", description = "Remove an IP address from the blocked list")
    @PostMapping("/unblock-ip")
    @RequiresRole("ADMIN")
    public ResponseEntity<Map<String, String>> unblockIP(@RequestParam String ip) {
        Map<String, String> response = new HashMap<>();
        
        try {
            // Remove from blocked IPs set
            redisTemplate.opsForSet().remove("blocked_ips", ip);
            
            // Remove block reason
            redisTemplate.delete("blocked:" + ip);
            
            response.put("status", "success");
            response.put("message", String.format("IP %s has been unblocked", ip));
            response.put("ip", ip);
            
            log.info("IP {} unblocked by admin", ip);
            
        } catch (Exception e) {
            log.error("Error unblocking IP: " + ip, e);
            response.put("status", "error");
            response.put("message", "Failed to unblock IP: " + e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * Get recent security events
     */
    @Operation(summary = "Get recent security events", description = "Returns recent security events and incidents")
    @GetMapping("/events")
    @RequiresRole("ADMIN")
    public ResponseEntity<Map<String, Object>> getRecentSecurityEvents(
            @RequestParam(defaultValue = "100") int limit) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // Get recent authentication failures
            Set<String> authFailures = redisTemplate.opsForSet().members("auth_failures:recent");
            
            // Get recent rate limit violations
            Set<String> rateLimitViolations = redisTemplate.opsForSet().members("rate_limit_violations:recent");
            
            // Get recent DDoS suspects
            Set<String> ddosSuspects = redisTemplate.opsForSet().members("ddos_suspects");
            
            // Get recent suspicious activities
            Set<String> suspiciousActivities = redisTemplate.opsForSet().members("suspicious_activities:recent");
            
            response.put("authenticationFailures", authFailures);
            response.put("rateLimitViolations", rateLimitViolations);
            response.put("ddosSuspects", ddosSuspects);
            response.put("suspiciousActivities", suspiciousActivities);
            response.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            
        } catch (Exception e) {
            log.error("Error retrieving security events", e);
            response.put("error", "Failed to retrieve security events");
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * Test security alert system
     */
    @Operation(summary = "Test security alerts", description = "Send a test security alert to verify alerting system")
    @PostMapping("/test-alert")
    @RequiresRole("ADMIN")
    public ResponseEntity<Map<String, String>> testAlert(
            @RequestParam(defaultValue = "MEDIUM") String severity,
            @RequestParam(defaultValue = "Test Alert") String title,
            @RequestParam(defaultValue = "This is a test security alert") String message) {
        
        Map<String, String> response = new HashMap<>();
        
        try {
            Map<String, String> details = new HashMap<>();
            details.put("test", "true");
            details.put("triggeredBy", "admin");
            details.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            
            switch (severity.toUpperCase()) {
                case "CRITICAL":
                    alertManager.sendCriticalAlert(title, message, details);
                    break;
                case "HIGH":
                    alertManager.sendHighAlert(title, message, details);
                    break;
                case "MEDIUM":
                default:
                    alertManager.sendMediumAlert(title, message, details);
                    break;
            }
            
            response.put("status", "success");
            response.put("message", "Test alert sent successfully");
            response.put("severity", severity);
            response.put("title", title);
            
            log.info("Test security alert sent: {} - {}", severity, title);
            
        } catch (Exception e) {
            log.error("Error sending test alert", e);
            response.put("status", "error");
            response.put("message", "Failed to send test alert: " + e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * Get monitoring configuration status
     */
    @Operation(summary = "Get monitoring configuration", description = "Returns current monitoring configuration and status")
    @GetMapping("/config")
    @RequiresRole("ADMIN")
    public ResponseEntity<Map<String, Object>> getMonitoringConfig() {
        Map<String, Object> config = new HashMap<>();
        
        config.put("authFailureThreshold", 10);
        config.put("rateLimitThreshold", 20);
        config.put("ddosThreshold", 5);
        config.put("suspiciousActivityThreshold", 15);
        config.put("monitoringWindow", "5 minutes");
        config.put("alertingEnabled", true);
        config.put("emailAlertsEnabled", false);
        config.put("webhookConfigured", false);
        config.put("slackConfigured", false);
        config.put("teamsConfigured", false);
        
        return ResponseEntity.ok(config);
    }
}