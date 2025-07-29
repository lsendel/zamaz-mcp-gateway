package com.zamaz.mcp.gateway.filter;

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
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * DDoS protection filter implementing various defensive strategies.
 * Works in conjunction with RateLimitingFilter for comprehensive protection.
 */
@Component
@Order(2)
@RequiredArgsConstructor
@Slf4j
public class DDoSProtectionFilter extends OncePerRequestFilter {

    private final RedisTemplate<String, String> redisTemplate;
    private final SecurityAuditLogger auditLogger;

    @Value("${ddos.protection.enabled:true}")
    private boolean ddosProtectionEnabled;

    @Value("${ddos.max-connections-per-ip:50}")
    private int maxConnectionsPerIp;

    @Value("${ddos.request-size-limit:1048576}") // 1MB default
    private int requestSizeLimit;

    @Value("${ddos.suspicious-pattern-threshold:5}")
    private int suspiciousPatternThreshold;

    private static final String CONNECTION_COUNT_PREFIX = "ddos:connections:";
    private static final String PATTERN_COUNT_PREFIX = "ddos:patterns:";
    private static final String BLOCKED_PREFIX = "ddos:blocked:";
    
    // Suspicious patterns that might indicate attacks
    private static final Pattern[] SUSPICIOUS_PATTERNS = {
        Pattern.compile(".*\\.\\.[\\\\/].*"), // Path traversal
        Pattern.compile(".*[<>\"'`].*"), // XSS attempts
        Pattern.compile(".*union.*select.*", Pattern.CASE_INSENSITIVE), // SQL injection
        Pattern.compile(".*\\bor\\b.*\\b1\\s*=\\s*1.*", Pattern.CASE_INSENSITIVE), // SQL injection
        Pattern.compile(".*<script.*>.*</script>.*", Pattern.CASE_INSENSITIVE), // XSS
        Pattern.compile(".*javascript:.*", Pattern.CASE_INSENSITIVE), // XSS
        Pattern.compile(".*\\bexec\\b.*\\bxp_.*", Pattern.CASE_INSENSITIVE), // SQL Server injection
        Pattern.compile(".*\\bdrop\\b.*\\btable\\b.*", Pattern.CASE_INSENSITIVE) // SQL injection
    };

    // Known attack user agents
    private static final String[] ATTACK_USER_AGENTS = {
        "nikto", "sqlmap", "nmap", "masscan", "metasploit",
        "havij", "acunetix", "nessus", "openvas", "w3af"
    };

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException {
        
        if (!ddosProtectionEnabled) {
            filterChain.doFilter(request, response);
            return;
        }

        String clientIp = getClientIp(request);
        
        // Check if IP is already blocked
        if (isBlocked(clientIp)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            log.warn("Blocked request from IP: {}", clientIp);
            return;
        }

        // Check connection count per IP
        if (!checkConnectionLimit(clientIp)) {
            blockIp(clientIp, "Exceeded connection limit");
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            auditLogger.logSuspiciousActivity("DDOS_CONNECTION_FLOOD", 
                Map.of("ip", clientIp, "connections", maxConnectionsPerIp));
            return;
        }

        // Check request size
        if (request.getContentLength() > requestSizeLimit) {
            response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
            auditLogger.logSuspiciousActivity("OVERSIZED_REQUEST", 
                Map.of("ip", clientIp, "size", request.getContentLength()));
            return;
        }

        // Check for known attack patterns
        if (containsSuspiciousPatterns(request)) {
            incrementPatternCount(clientIp);
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            auditLogger.logSuspiciousActivity("ATTACK_PATTERN_DETECTED", 
                Map.of("ip", clientIp, "uri", request.getRequestURI()));
            return;
        }

        // Check for known attack tools
        if (isKnownAttackTool(request)) {
            blockIp(clientIp, "Known attack tool detected");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            auditLogger.logSecurityViolation("ATTACK_TOOL_DETECTED", 
                Map.of("ip", clientIp, "userAgent", request.getHeader("User-Agent")));
            return;
        }

        // Check for rapid-fire requests (complementary to rate limiting)
        if (isRapidFire(clientIp)) {
            response.setStatus(HttpServletResponse.SC_TOO_MANY_REQUESTS);
            response.setHeader("Retry-After", "60");
            return;
        }

        // Track connection
        trackConnection(clientIp);
        
        try {
            filterChain.doFilter(request, response);
        } finally {
            // Release connection
            releaseConnection(clientIp);
        }
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
     * Check if IP is blocked.
     */
    private boolean isBlocked(String ip) {
        String key = BLOCKED_PREFIX + ip;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    /**
     * Block an IP address.
     */
    private void blockIp(String ip, String reason) {
        String key = BLOCKED_PREFIX + ip;
        redisTemplate.opsForValue().set(key, reason, 1, TimeUnit.HOURS);
        log.warn("Blocked IP {} for: {}", ip, reason);
    }

    /**
     * Check connection limit per IP.
     */
    private boolean checkConnectionLimit(String ip) {
        String key = CONNECTION_COUNT_PREFIX + ip;
        Long connections = redisTemplate.opsForValue().increment(key);
        
        if (connections == 1) {
            redisTemplate.expire(key, 1, TimeUnit.MINUTES);
        }
        
        return connections <= maxConnectionsPerIp;
    }

    /**
     * Track active connection.
     */
    private void trackConnection(String ip) {
        String key = CONNECTION_COUNT_PREFIX + "active:" + ip;
        redisTemplate.opsForValue().increment(key);
        redisTemplate.expire(key, 5, TimeUnit.MINUTES);
    }

    /**
     * Release connection when request completes.
     */
    private void releaseConnection(String ip) {
        String key = CONNECTION_COUNT_PREFIX + "active:" + ip;
        Long count = redisTemplate.opsForValue().decrement(key);
        if (count != null && count <= 0) {
            redisTemplate.delete(key);
        }
    }

    /**
     * Check for suspicious patterns in request.
     */
    private boolean containsSuspiciousPatterns(HttpServletRequest request) {
        // Check URI
        String uri = request.getRequestURI();
        String queryString = request.getQueryString();
        
        for (Pattern pattern : SUSPICIOUS_PATTERNS) {
            if (pattern.matcher(uri).matches()) {
                return true;
            }
            if (queryString != null && pattern.matcher(queryString).matches()) {
                return true;
            }
        }
        
        // Check common headers
        String[] headersToCheck = {"Referer", "X-Forwarded-For", "X-Real-IP"};
        for (String header : headersToCheck) {
            String value = request.getHeader(header);
            if (value != null) {
                for (Pattern pattern : SUSPICIOUS_PATTERNS) {
                    if (pattern.matcher(value).matches()) {
                        return true;
                    }
                }
            }
        }
        
        return false;
    }

    /**
     * Increment pattern detection count.
     */
    private void incrementPatternCount(String ip) {
        String key = PATTERN_COUNT_PREFIX + ip;
        Long count = redisTemplate.opsForValue().increment(key);
        
        if (count == 1) {
            redisTemplate.expire(key, 1, TimeUnit.HOURS);
        }
        
        if (count >= suspiciousPatternThreshold) {
            blockIp(ip, "Too many suspicious patterns");
        }
    }

    /**
     * Check if request is from known attack tool.
     */
    private boolean isKnownAttackTool(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        if (userAgent == null) {
            return false;
        }
        
        String lowerUserAgent = userAgent.toLowerCase();
        for (String attackAgent : ATTACK_USER_AGENTS) {
            if (lowerUserAgent.contains(attackAgent)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check for rapid-fire requests (multiple requests in very short time).
     */
    private boolean isRapidFire(String ip) {
        String key = "rapid:" + ip;
        Long count = redisTemplate.opsForValue().increment(key);
        
        if (count == 1) {
            redisTemplate.expire(key, 100, TimeUnit.MILLISECONDS);
        }
        
        // More than 5 requests in 100ms is suspicious
        return count > 5;
    }
}