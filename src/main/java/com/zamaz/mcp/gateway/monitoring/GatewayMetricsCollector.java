package com.zamaz.mcp.gateway.monitoring;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.concurrent.TimeUnit;

/**
 * Global filter for collecting gateway metrics.
 * Tracks request counts, latencies, and error rates per route.
 */
@Component
public class GatewayMetricsCollector implements GlobalFilter, Ordered {
    
    private final MeterRegistry meterRegistry;
    
    // Metric names
    private static final String REQUEST_COUNTER = "gateway.requests.total";
    private static final String REQUEST_TIMER = "gateway.requests.duration";
    private static final String ERROR_COUNTER = "gateway.errors.total";
    private static final String RATE_LIMIT_COUNTER = "gateway.ratelimit.exceeded";
    private static final String CIRCUIT_BREAKER_COUNTER = "gateway.circuitbreaker.triggered";
    
    public GatewayMetricsCollector(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }
    
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        long startTime = System.nanoTime();
        
        return chain.filter(exchange)
            .doOnSuccess(aVoid -> recordMetrics(exchange, startTime, false))
            .doOnError(throwable -> recordMetrics(exchange, startTime, true))
            .doFinally(signalType -> {
                // Additional metrics based on response status
                HttpStatus status = exchange.getResponse().getStatusCode();
                if (status != null) {
                    if (status == HttpStatus.TOO_MANY_REQUESTS) {
                        incrementRateLimitCounter(exchange);
                    } else if (status == HttpStatus.SERVICE_UNAVAILABLE) {
                        incrementCircuitBreakerCounter(exchange);
                    }
                }
            });
    }
    
    private void recordMetrics(ServerWebExchange exchange, long startTime, boolean isError) {
        long duration = System.nanoTime() - startTime;
        
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        String routeId = route != null ? route.getId() : "unknown";
        String method = exchange.getRequest().getMethod().toString();
        String path = exchange.getRequest().getPath().value();
        HttpStatus status = exchange.getResponse().getStatusCode();
        String statusCode = status != null ? String.valueOf(status.value()) : "unknown";
        
        // Record request count
        Counter.builder(REQUEST_COUNTER)
            .tag("route", routeId)
            .tag("method", method)
            .tag("status", statusCode)
            .tag("path", normalizePathForMetrics(path))
            .register(meterRegistry)
            .increment();
        
        // Record request duration
        Timer.builder(REQUEST_TIMER)
            .tag("route", routeId)
            .tag("method", method)
            .tag("status", statusCode)
            .register(meterRegistry)
            .record(duration, TimeUnit.NANOSECONDS);
        
        // Record errors
        if (isError || (status != null && status.is5xxServerError())) {
            Counter.builder(ERROR_COUNTER)
                .tag("route", routeId)
                .tag("method", method)
                .tag("path", normalizePathForMetrics(path))
                .register(meterRegistry)
                .increment();
        }
    }
    
    private void incrementRateLimitCounter(ServerWebExchange exchange) {
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        String routeId = route != null ? route.getId() : "unknown";
        
        Counter.builder(RATE_LIMIT_COUNTER)
            .tag("route", routeId)
            .tag("method", exchange.getRequest().getMethod().toString())
            .register(meterRegistry)
            .increment();
    }
    
    private void incrementCircuitBreakerCounter(ServerWebExchange exchange) {
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        String routeId = route != null ? route.getId() : "unknown";
        
        Counter.builder(CIRCUIT_BREAKER_COUNTER)
            .tag("route", routeId)
            .register(meterRegistry)
            .increment();
    }
    
    private String normalizePathForMetrics(String path) {
        // Remove specific IDs from paths to avoid high cardinality
        return path
            .replaceAll("/\\d+", "/{id}")
            .replaceAll("/[a-f0-9-]{36}", "/{uuid}");
    }
    
    @Override
    public int getOrder() {
        // Run early in the filter chain to capture all requests
        return Ordered.HIGHEST_PRECEDENCE;
    }
}