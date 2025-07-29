package com.zamaz.mcp.gateway.controller;

import com.zamaz.mcp.security.annotation.RequiresPermission;
import com.zamaz.mcp.security.rbac.Permission;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Controller for managing security features like rate limiting and DDoS protection.
 */
@RestController
@RequestMapping("/api/v1/security")
@RequiredArgsConstructor
@Slf4j
public class SecurityManagementController {

    private final RedisTemplate<String, String> redisTemplate;

    /**
     * Get rate limiting status and statistics.
     */
    @GetMapping("/rate-limit/status")
    @RequiresPermission(Permission.SYSTEM_ADMIN)
    public ResponseEntity<Map<String, Object>> getRateLimitStatus() {
        Map<String, Object> status = new HashMap<>();
        
        // Get current rate limit violations
        Set<String> violationKeys = redisTemplate.keys("violations:*");
        Map<String, Integer> violations = new HashMap<>();
        
        if (violationKeys != null) {
            for (String key : violationKeys) {
                String clientId = key.substring("violations:".length());
                String count = redisTemplate.opsForValue().get(key);
                violations.put(clientId, count != null ? Integer.parseInt(count) : 0);
            }
        }
        
        // Get blacklisted IPs
        Set<String> blacklistKeys = redisTemplate.keys("blacklist:*");
        List<Map<String, Object>> blacklisted = new ArrayList<>();
        
        if (blacklistKeys != null) {
            for (String key : blacklistKeys) {
                String clientId = key.substring("blacklist:".length());
                String reason = redisTemplate.opsForValue().get(key);
                Long ttl = redisTemplate.getExpire(key);
                
                Map<String, Object> entry = new HashMap<>();
                entry.put("clientId", clientId);
                entry.put("reason", reason);
                entry.put("expiresIn", ttl);
                blacklisted.add(entry);
            }
        }
        
        status.put("violations", violations);
        status.put("blacklisted", blacklisted);
        status.put("timestamp", System.currentTimeMillis());
        
        return ResponseEntity.ok(status);
    }

    /**
     * Get DDoS protection statistics.
     */
    @GetMapping("/ddos/status")
    @RequiresPermission(Permission.SYSTEM_ADMIN)
    public ResponseEntity<Map<String, Object>> getDDoSStatus() {
        Map<String, Object> status = new HashMap<>();
        
        // Get blocked IPs
        Set<String> blockedKeys = redisTemplate.keys("ddos:blocked:*");
        List<Map<String, Object>> blocked = new ArrayList<>();
        
        if (blockedKeys != null) {
            for (String key : blockedKeys) {
                String ip = key.substring("ddos:blocked:".length());
                String reason = redisTemplate.opsForValue().get(key);
                Long ttl = redisTemplate.getExpire(key);
                
                Map<String, Object> entry = new HashMap<>();
                entry.put("ip", ip);
                entry.put("reason", reason);
                entry.put("expiresIn", ttl);
                blocked.add(entry);
            }
        }
        
        // Get connection counts
        Set<String> connectionKeys = redisTemplate.keys("ddos:connections:*");
        Map<String, Integer> connections = new HashMap<>();
        
        if (connectionKeys != null) {
            for (String key : connectionKeys) {
                String ip = key.substring("ddos:connections:".length());
                String count = redisTemplate.opsForValue().get(key);
                connections.put(ip, count != null ? Integer.parseInt(count) : 0);
            }
        }
        
        status.put("blocked", blocked);
        status.put("connections", connections);
        status.put("timestamp", System.currentTimeMillis());
        
        return ResponseEntity.ok(status);
    }

    /**
     * Get circuit breaker status.
     */
    @GetMapping("/circuit-breaker/status")
    @RequiresPermission(Permission.SYSTEM_ADMIN)
    public ResponseEntity<Map<String, Object>> getCircuitBreakerStatus() {
        Map<String, Object> status = new HashMap<>();
        
        // Get circuit states
        Set<String> circuitKeys = redisTemplate.keys("circuit:*:state");
        Map<String, Object> circuits = new HashMap<>();
        
        if (circuitKeys != null) {
            for (String key : circuitKeys) {
                // Extract service name from "circuit:serviceName:state"
                String serviceName = key.substring("circuit:".length(), key.lastIndexOf(":state"));
                String state = redisTemplate.opsForValue().get(key);
                Long ttl = redisTemplate.getExpire(key);
                
                Map<String, Object> circuitInfo = new HashMap<>();
                circuitInfo.put("state", state);
                circuitInfo.put("ttl", ttl);
                
                // Get failure count
                String failureKey = "circuit:failures:" + serviceName;
                String failures = redisTemplate.opsForValue().get(failureKey);
                circuitInfo.put("failures", failures != null ? Integer.parseInt(failures) : 0);
                
                // Get success count
                String successKey = "circuit:success:" + serviceName;
                String successes = redisTemplate.opsForValue().get(successKey);
                circuitInfo.put("successes", successes != null ? Integer.parseInt(successes) : 0);
                
                circuits.put(serviceName, circuitInfo);
            }
        }
        
        status.put("circuits", circuits);
        status.put("timestamp", System.currentTimeMillis());
        
        return ResponseEntity.ok(status);
    }

    /**
     * Manually block an IP address.
     */
    @PostMapping("/block-ip")
    @RequiresPermission(Permission.SYSTEM_ADMIN)
    public ResponseEntity<Map<String, Object>> blockIp(
            @RequestParam String ip,
            @RequestParam(defaultValue = "Manual block") String reason,
            @RequestParam(defaultValue = "3600") long durationSeconds) {
        
        String key = "blacklist:ip:" + ip;
        redisTemplate.opsForValue().set(key, reason, durationSeconds, TimeUnit.SECONDS);
        
        log.info("Manually blocked IP: {} for reason: {} duration: {}s", ip, reason, durationSeconds);
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("ip", ip);
        response.put("reason", reason);
        response.put("expiresIn", durationSeconds);
        
        return ResponseEntity.ok(response);
    }

    /**
     * Unblock an IP address.
     */
    @DeleteMapping("/block-ip")
    @RequiresPermission(Permission.SYSTEM_ADMIN)
    public ResponseEntity<Map<String, Object>> unblockIp(@RequestParam String ip) {
        String key = "blacklist:ip:" + ip;
        Boolean deleted = redisTemplate.delete(key);
        
        // Also remove from DDoS blocks
        String ddosKey = "ddos:blocked:" + ip;
        redisTemplate.delete(ddosKey);
        
        log.info("Manually unblocked IP: {}", ip);
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", deleted != null && deleted);
        response.put("ip", ip);
        
        return ResponseEntity.ok(response);
    }

    /**
     * Reset circuit breaker for a service.
     */
    @PostMapping("/circuit-breaker/reset")
    @RequiresPermission(Permission.SYSTEM_ADMIN)
    public ResponseEntity<Map<String, Object>> resetCircuitBreaker(@RequestParam String service) {
        // Delete circuit state
        redisTemplate.delete("circuit:" + service + ":state");
        
        // Clear counters
        redisTemplate.delete("circuit:failures:" + service);
        redisTemplate.delete("circuit:success:" + service);
        redisTemplate.delete("circuit:halfopen:" + service);
        
        log.info("Reset circuit breaker for service: {}", service);
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("service", service);
        response.put("newState", "CLOSED");
        
        return ResponseEntity.ok(response);
    }

    /**
     * Clear all rate limiting data for a client.
     */
    @DeleteMapping("/rate-limit/clear")
    @RequiresPermission(Permission.SYSTEM_ADMIN)
    public ResponseEntity<Map<String, Object>> clearRateLimit(@RequestParam String clientId) {
        // Clear rate limit counters
        Set<String> keys = redisTemplate.keys("rate_limit:" + clientId + "*");
        if (keys != null && !keys.isEmpty()) {
            redisTemplate.delete(keys);
        }
        
        // Clear violations
        redisTemplate.delete("violations:" + clientId);
        
        // Clear burst limits
        redisTemplate.delete("burst:" + clientId);
        
        log.info("Cleared rate limit data for client: {}", clientId);
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("clientId", clientId);
        response.put("clearedKeys", keys != null ? keys.size() : 0);
        
        return ResponseEntity.ok(response);
    }

    /**
     * Get security metrics summary.
     */
    @GetMapping("/metrics")
    @RequiresPermission(Permission.SYSTEM_ADMIN)
    public ResponseEntity<Map<String, Object>> getSecurityMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        // Count total violations
        Set<String> violationKeys = redisTemplate.keys("violations:*");
        int totalViolations = violationKeys != null ? violationKeys.size() : 0;
        
        // Count blocked IPs
        Set<String> blacklistKeys = redisTemplate.keys("blacklist:*");
        int blockedIPs = blacklistKeys != null ? blacklistKeys.size() : 0;
        
        // Count DDoS blocked IPs
        Set<String> ddosBlockedKeys = redisTemplate.keys("ddos:blocked:*");
        int ddosBlocked = ddosBlockedKeys != null ? ddosBlockedKeys.size() : 0;
        
        // Count circuit breakers
        Set<String> circuitKeys = redisTemplate.keys("circuit:*:state");
        int openCircuits = 0;
        if (circuitKeys != null) {
            for (String key : circuitKeys) {
                String state = redisTemplate.opsForValue().get(key);
                if ("OPEN".equals(state)) {
                    openCircuits++;
                }
            }
        }
        
        metrics.put("totalViolations", totalViolations);
        metrics.put("blockedIPs", blockedIPs);
        metrics.put("ddosBlocked", ddosBlocked);
        metrics.put("openCircuits", openCircuits);
        metrics.put("timestamp", System.currentTimeMillis());
        
        return ResponseEntity.ok(metrics);
    }

    /**
     * Emergency mode - block all non-authenticated requests.
     */
    @PostMapping("/emergency-mode")
    @RequiresPermission(Permission.SYSTEM_ADMIN)
    public ResponseEntity<Map<String, Object>> enableEmergencyMode(
            @RequestParam(defaultValue = "true") boolean enabled,
            @RequestParam(defaultValue = "3600") long durationSeconds) {
        
        String key = "emergency:mode";
        if (enabled) {
            redisTemplate.opsForValue().set(key, "enabled", durationSeconds, TimeUnit.SECONDS);
            log.warn("Emergency mode ENABLED for {} seconds", durationSeconds);
        } else {
            redisTemplate.delete(key);
            log.info("Emergency mode DISABLED");
        }
        
        Map<String, Object> response = new HashMap<>();
        response.put("emergencyMode", enabled);
        response.put("duration", enabled ? durationSeconds : 0);
        
        return ResponseEntity.ok(response);
    }
}