package com.zamaz.mcp.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;

/**
 * Gateway filter for adding security headers to all responses.
 * Implements defense-in-depth by ensuring security headers are present.
 */
@Component
public class SecurityHeadersGatewayFilterFactory 
    extends AbstractGatewayFilterFactory<SecurityHeadersGatewayFilterFactory.Config> {
    
    public SecurityHeadersGatewayFilterFactory() {
        super(Config.class);
    }
    
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> chain.filter(exchange).then(
            Mono.fromRunnable(() -> {
                HttpHeaders headers = exchange.getResponse().getHeaders();
                
                // X-Content-Type-Options
                if (!headers.containsKey("X-Content-Type-Options")) {
                    headers.add("X-Content-Type-Options", "nosniff");
                }
                
                // X-Frame-Options
                if (!headers.containsKey("X-Frame-Options")) {
                    headers.add("X-Frame-Options", config.getFrameOptions());
                }
                
                // X-XSS-Protection
                if (!headers.containsKey("X-XSS-Protection")) {
                    headers.add("X-XSS-Protection", "1; mode=block");
                }
                
                // Referrer-Policy
                if (!headers.containsKey("Referrer-Policy")) {
                    headers.add("Referrer-Policy", config.getReferrerPolicy());
                }
                
                // Content-Security-Policy
                if (config.isEnableCsp() && !headers.containsKey("Content-Security-Policy")) {
                    headers.add("Content-Security-Policy", config.getContentSecurityPolicy());
                }
                
                // Strict-Transport-Security (only for HTTPS)
                if (config.isEnableHsts() && 
                    "https".equalsIgnoreCase(exchange.getRequest().getURI().getScheme()) &&
                    !headers.containsKey("Strict-Transport-Security")) {
                    headers.add("Strict-Transport-Security", 
                        "max-age=" + config.getHstsMaxAge() + "; includeSubDomains");
                }
                
                // Permissions-Policy
                if (config.isEnablePermissionsPolicy() && 
                    !headers.containsKey("Permissions-Policy")) {
                    headers.add("Permissions-Policy", config.getPermissionsPolicy());
                }
                
                // Remove potentially dangerous headers
                config.getHeadersToRemove().forEach(headers::remove);
            })
        );
    }
    
    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList("enabled");
    }
    
    public static class Config {
        private boolean enabled = true;
        private String frameOptions = "DENY";
        private String referrerPolicy = "strict-origin-when-cross-origin";
        private boolean enableCsp = true;
        private String contentSecurityPolicy = 
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; " +
            "font-src 'self' data:; connect-src 'self' https://api.anthropic.com; " +
            "frame-ancestors 'none';";
        private boolean enableHsts = true;
        private long hstsMaxAge = 31536000; // 1 year
        private boolean enablePermissionsPolicy = true;
        private String permissionsPolicy = 
            "geolocation=(), microphone=(), camera=(), payment=(), usb=()";
        private List<String> headersToRemove = Arrays.asList(
            "Server", "X-Powered-By", "X-AspNet-Version"
        );
        
        // Getters and setters
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        
        public String getFrameOptions() { return frameOptions; }
        public void setFrameOptions(String frameOptions) { this.frameOptions = frameOptions; }
        
        public String getReferrerPolicy() { return referrerPolicy; }
        public void setReferrerPolicy(String referrerPolicy) { this.referrerPolicy = referrerPolicy; }
        
        public boolean isEnableCsp() { return enableCsp; }
        public void setEnableCsp(boolean enableCsp) { this.enableCsp = enableCsp; }
        
        public String getContentSecurityPolicy() { return contentSecurityPolicy; }
        public void setContentSecurityPolicy(String contentSecurityPolicy) { 
            this.contentSecurityPolicy = contentSecurityPolicy; 
        }
        
        public boolean isEnableHsts() { return enableHsts; }
        public void setEnableHsts(boolean enableHsts) { this.enableHsts = enableHsts; }
        
        public long getHstsMaxAge() { return hstsMaxAge; }
        public void setHstsMaxAge(long hstsMaxAge) { this.hstsMaxAge = hstsMaxAge; }
        
        public boolean isEnablePermissionsPolicy() { return enablePermissionsPolicy; }
        public void setEnablePermissionsPolicy(boolean enablePermissionsPolicy) { 
            this.enablePermissionsPolicy = enablePermissionsPolicy; 
        }
        
        public String getPermissionsPolicy() { return permissionsPolicy; }
        public void setPermissionsPolicy(String permissionsPolicy) { 
            this.permissionsPolicy = permissionsPolicy; 
        }
        
        public List<String> getHeadersToRemove() { return headersToRemove; }
        public void setHeadersToRemove(List<String> headersToRemove) { 
            this.headersToRemove = headersToRemove; 
        }
    }
}