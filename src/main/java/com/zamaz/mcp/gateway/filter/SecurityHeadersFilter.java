package com.zamaz.mcp.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import java.util.UUID;

/**
 * Security Headers Filter for API Gateway
 * Adds essential security headers to all responses
 */
@Component
@Slf4j
public class SecurityHeadersFilter extends AbstractGatewayFilterFactory<SecurityHeadersFilter.Config> {

    public SecurityHeadersFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            // Add request ID for tracing
            String requestId = UUID.randomUUID().toString();
            ServerWebExchange enrichedExchange = exchange.mutate()
                .request(builder -> builder.header("X-Request-ID", requestId))
                .build();

            return chain.filter(enrichedExchange).doFinally(signalType -> {
                // Add security headers to response
                HttpHeaders headers = exchange.getResponse().getHeaders();
                
                // Request tracking
                headers.add("X-Request-ID", requestId);
                
                // Security headers
                headers.add("X-Content-Type-Options", "nosniff");
                headers.add("X-Frame-Options", "DENY");
                headers.add("X-XSS-Protection", "1; mode=block");
                headers.add("Referrer-Policy", "strict-origin-when-cross-origin");
                headers.add("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
                
                // Content Security Policy
                if (config.isEnableCSP()) {
                    String csp = "default-src 'self'; " +
                               "script-src 'self' 'unsafe-inline'; " +
                               "style-src 'self' 'unsafe-inline'; " +
                               "img-src 'self' data: https:; " +
                               "connect-src 'self' https:; " +
                               "font-src 'self'; " +
                               "object-src 'none'; " +
                               "base-uri 'self'; " +
                               "form-action 'self'";
                    headers.add("Content-Security-Policy", csp);
                }
                
                // HTTPS enforcement in production
                String environment = System.getenv("ENVIRONMENT");
                if (config.isEnableHSTS() && "production".equalsIgnoreCase(environment)) {
                    headers.add("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
                }
                
                // API-specific headers
                headers.add("Cache-Control", "no-cache, no-store, must-revalidate");
                headers.add("Pragma", "no-cache");
                headers.add("Expires", "0");
                
                // Rate limiting information
                headers.add("X-Rate-Limit-Limit", "100");
                
                log.debug("Security headers added to response for request: {}", requestId);
            });
        };
    }

    public static class Config {
        private boolean enableHSTS = true;
        private boolean enableCSP = true;
        
        public boolean isEnableHSTS() {
            return enableHSTS;
        }
        
        public void setEnableHSTS(boolean enableHSTS) {
            this.enableHSTS = enableHSTS;
        }
        
        public boolean isEnableCSP() {
            return enableCSP;
        }
        
        public void setEnableCSP(boolean enableCSP) {
            this.enableCSP = enableCSP;
        }
    }
}