package com.zamaz.mcp.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Request Validation Filter
 * Validates and sanitizes incoming requests for security
 */
@Component
@Slf4j
public class RequestValidationFilter extends AbstractGatewayFilterFactory<RequestValidationFilter.Config> {

    // Security patterns to detect potential attacks
    private static final List<Pattern> MALICIOUS_PATTERNS = List.of(
        Pattern.compile(".*<script[^>]*>.*</script>.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*javascript:.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*on\\w+\\s*=.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*union\\s+select.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*\\s+or\\s+1\\s*=\\s*1.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*\\.\.[\\/\\\\].*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*\\$\\{.*\\}.*", Pattern.CASE_INSENSITIVE) // Expression injection
    );

    // Suspicious user agents
    private static final List<Pattern> SUSPICIOUS_USER_AGENTS = List.of(
        Pattern.compile(".*sqlmap.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*nikto.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*nmap.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*burp.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*acunetix.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*nessus.*", Pattern.CASE_INSENSITIVE)
    );

    public RequestValidationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            
            // Validate request size
            if (isRequestTooLarge(request)) {
                log.warn("Request too large from IP: {}", getClientIP(request));
                return handleSecurityViolation(exchange, "Request size exceeds limit");
            }
            
            // Check for malicious patterns in URL
            String path = request.getURI().getPath();
            String query = request.getURI().getQuery();
            
            if (containsMaliciousContent(path) || containsMaliciousContent(query)) {
                log.warn("Malicious content detected in request from IP: {} - Path: {}", 
                    getClientIP(request), path);
                return handleSecurityViolation(exchange, "Malicious content detected");
            }
            
            // Check for suspicious user agents
            String userAgent = request.getHeaders().getFirst("User-Agent");
            if (isSuspiciousUserAgent(userAgent)) {
                log.warn("Suspicious user agent detected: {} from IP: {}", 
                    userAgent, getClientIP(request));
                return handleSecurityViolation(exchange, "Suspicious user agent");
            }
            
            // Validate headers
            if (hasInvalidHeaders(request)) {
                log.warn("Invalid headers detected from IP: {}", getClientIP(request));
                return handleSecurityViolation(exchange, "Invalid headers");
            }
            
            // Check for request method abuse
            if (isMethodNotAllowed(request)) {
                log.warn("Method not allowed: {} from IP: {}", 
                    request.getMethod(), getClientIP(request));
                return handleSecurityViolation(exchange, "Method not allowed");
            }
            
            // Log security metrics
            log.debug("Request validated - IP: {}, Path: {}, Method: {}", 
                getClientIP(request), path, request.getMethod());
            
            return chain.filter(exchange);
        };
    }
    
    private boolean isRequestTooLarge(ServerHttpRequest request) {
        String contentLength = request.getHeaders().getFirst("Content-Length");
        if (contentLength != null) {
            try {
                long length = Long.parseLong(contentLength);
                return length > 10_000_000; // 10MB limit
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return false;
    }
    
    private boolean containsMaliciousContent(String content) {
        if (content == null) return false;
        
        return MALICIOUS_PATTERNS.stream()
            .anyMatch(pattern -> pattern.matcher(content).matches());
    }
    
    private boolean isSuspiciousUserAgent(String userAgent) {
        if (userAgent == null) return false;
        
        return SUSPICIOUS_USER_AGENTS.stream()
            .anyMatch(pattern -> pattern.matcher(userAgent).matches());
    }
    
    private boolean hasInvalidHeaders(ServerHttpRequest request) {
        // Check for headers that might indicate attack attempts
        String host = request.getHeaders().getFirst("Host");
        if (host != null && (host.contains("..\\"))) {
            return true;
        }
        
        // Check for overly long headers
        return request.getHeaders().entrySet().stream()
            .anyMatch(entry -> entry.getValue().stream()
                .anyMatch(value -> value.length() > 8192)); // 8KB header limit
    }
    
    private boolean isMethodNotAllowed(ServerHttpRequest request) {
        // Only allow specific HTTP methods
        String method = request.getMethod().toString();
        List<String> allowedMethods = List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD");
        return !allowedMethods.contains(method);
    }
    
    private String getClientIP(ServerHttpRequest request) {
        // Check for forwarded headers first
        String xForwardedFor = request.getHeaders().getFirst("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIP = request.getHeaders().getFirst("X-Real-IP");
        if (xRealIP != null && !xRealIP.isEmpty()) {
            return xRealIP;
        }
        
        // Fallback to remote address
        return request.getRemoteAddress() != null 
            ? request.getRemoteAddress().getAddress().getHostAddress() 
            : "unknown";
    }
    
    private Mono<Void> handleSecurityViolation(ServerWebExchange exchange, String reason) {
        exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        
        String body = String.format(
            "{\"error\":\"Security Violation\",\"message\":\"%s\",\"timestamp\":\"%s\"}",
            reason, java.time.Instant.now().toString());
        
        var buffer = exchange.getResponse().bufferFactory().wrap(body.getBytes());
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    public static class Config {
        private long maxRequestSize = 10_000_000; // 10MB
        private int maxHeaderSize = 8192; // 8KB
        private boolean enablePatternValidation = true;
        private boolean enableUserAgentValidation = true;
        
        public long getMaxRequestSize() {
            return maxRequestSize;
        }
        
        public void setMaxRequestSize(long maxRequestSize) {
            this.maxRequestSize = maxRequestSize;
        }
        
        public int getMaxHeaderSize() {
            return maxHeaderSize;
        }
        
        public void setMaxHeaderSize(int maxHeaderSize) {
            this.maxHeaderSize = maxHeaderSize;
        }
        
        public boolean isEnablePatternValidation() {
            return enablePatternValidation;
        }
        
        public void setEnablePatternValidation(boolean enablePatternValidation) {
            this.enablePatternValidation = enablePatternValidation;
        }
        
        public boolean isEnableUserAgentValidation() {
            return enableUserAgentValidation;
        }
        
        public void setEnableUserAgentValidation(boolean enableUserAgentValidation) {
            this.enableUserAgentValidation = enableUserAgentValidation;
        }
    }
}
