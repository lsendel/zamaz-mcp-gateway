package com.zamaz.mcp.gateway.config;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import org.springframework.boot.actuate.autoconfigure.metrics.MeterRegistryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Metrics configuration for monitoring gateway performance
 */
@Configuration
public class MetricsConfig {
    
    /**
     * Customize meter registry with common tags
     */
    @Bean
    public MeterRegistryCustomizer<MeterRegistry> metricsCommonTags() {
        return registry -> registry.config().commonTags(
            "application", "mcp-gateway",
            "service", "gateway",
            "environment", System.getProperty("spring.profiles.active", "default")
        );
    }
    
    /**
     * Gateway-specific metrics collector
     */
    @Bean
    public GatewayMetricsCollector gatewayMetricsCollector(MeterRegistry meterRegistry) {
        return new GatewayMetricsCollector(meterRegistry);
    }
    
    /**
     * Custom metrics collector for gateway
     */
    public static class GatewayMetricsCollector {
        private final MeterRegistry meterRegistry;
        
        public GatewayMetricsCollector(MeterRegistry meterRegistry) {
            this.meterRegistry = meterRegistry;
        }
        
        public void recordRequest(String route, String method, int status, long duration) {
            meterRegistry.counter("gateway.requests.total",
                Tags.of("route", route, "method", method, "status", String.valueOf(status))
            ).increment();
            
            meterRegistry.timer("gateway.requests.duration",
                Tags.of("route", route, "method", method)
            ).record(duration, java.util.concurrent.TimeUnit.MILLISECONDS);
        }
        
        public void recordRateLimitHit(String key, boolean allowed) {
            meterRegistry.counter("gateway.ratelimit.requests",
                Tags.of("key", key, "allowed", String.valueOf(allowed))
            ).increment();
        }
        
        public void recordCircuitBreakerEvent(String service, String event) {
            meterRegistry.counter("gateway.circuitbreaker.events",
                Tags.of("service", service, "event", event)
            ).increment();
        }
        
        public void recordAuthenticationAttempt(boolean success, String reason) {
            meterRegistry.counter("gateway.auth.attempts",
                Tags.of("success", String.valueOf(success), "reason", reason)
            ).increment();
        }
    }
}