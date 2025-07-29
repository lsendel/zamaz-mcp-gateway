package com.zamaz.mcp.gateway.filter;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.reactor.circuitbreaker.operator.CircuitBreakerOperator;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Gateway filter implementing circuit breaker pattern for fault tolerance
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CircuitBreakerGatewayFilterFactory extends AbstractGatewayFilterFactory<CircuitBreakerGatewayFilterFactory.Config> {

    private final ConcurrentHashMap<String, CircuitBreaker> circuitBreakers = new ConcurrentHashMap<>();

    public CircuitBreakerGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            CircuitBreaker circuitBreaker = getOrCreateCircuitBreaker(config);
            
            return chain.filter(exchange)
                .transform(CircuitBreakerOperator.of(circuitBreaker))
                .onErrorResume(throwable -> {
                    log.error("Circuit breaker {} opened due to error: {}", config.getName(), throwable.getMessage());
                    
                    // Add circuit breaker status to response headers
                    exchange.getResponse().getHeaders().add("X-Circuit-Breaker", config.getName());
                    exchange.getResponse().getHeaders().add("X-Circuit-Breaker-Status", circuitBreaker.getState().toString());
                    
                    // Handle fallback
                    if (config.getFallbackUri() != null) {
                        return handleFallback(exchange, config);
                    }
                    
                    // Return error response
                    exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
                    exchange.getResponse().getHeaders().add("X-Error-Reason", "Circuit breaker open");
                    return exchange.getResponse().setComplete();
                });
        };
    }

    private CircuitBreaker getOrCreateCircuitBreaker(Config config) {
        return circuitBreakers.computeIfAbsent(config.getName(), name -> {
            CircuitBreakerConfig circuitBreakerConfig = CircuitBreakerConfig.custom()
                .failureRateThreshold(config.getFailureRateThreshold())
                .waitDurationInOpenState(config.getWaitDurationInOpenState())
                .permittedNumberOfCallsInHalfOpenState(config.getPermittedNumberOfCallsInHalfOpenState())
                .slidingWindowSize(config.getSlidingWindowSize())
                .slidingWindowType(config.getSlidingWindowType())
                .minimumNumberOfCalls(config.getMinimumNumberOfCalls())
                .slowCallDurationThreshold(config.getSlowCallDuration())
                .slowCallRateThreshold(config.getSlowCallRateThreshold())
                .automaticTransitionFromOpenToHalfOpenEnabled(config.isAutomaticTransitionEnabled())
                .recordExceptions(Exception.class)
                .ignoreExceptions(config.getIgnoreExceptions())
                .build();

            CircuitBreaker circuitBreaker = CircuitBreaker.of(name, circuitBreakerConfig);
            
            // Add event listeners
            circuitBreaker.getEventPublisher()
                .onStateTransition(event -> 
                    log.info("Circuit breaker {} transitioned from {} to {}", 
                        name, event.getStateTransition().getFromState(), event.getStateTransition().getToState()))
                .onFailureRateExceeded(event -> 
                    log.warn("Circuit breaker {} failure rate exceeded: {}%", 
                        name, event.getFailureRate()))
                .onSlowCallRateExceeded(event -> 
                    log.warn("Circuit breaker {} slow call rate exceeded: {}%", 
                        name, event.getSlowCallRate()));

            return circuitBreaker;
        });
    }

    private Mono<Void> handleFallback(ServerWebExchange exchange, Config config) {
        log.info("Executing fallback for circuit breaker: {}", config.getName());
        
        // Modify the request to route to fallback URI
        ServerWebExchange mutatedExchange = exchange.mutate()
            .request(r -> r.uri(java.net.URI.create(config.getFallbackUri())))
            .build();
        
        // Set fallback response headers
        mutatedExchange.getResponse().getHeaders().add("X-Fallback", "true");
        mutatedExchange.getResponse().getHeaders().add("X-Fallback-Reason", "Circuit breaker open");
        
        return mutatedExchange.getResponse().setComplete();
    }

    /**
     * Get circuit breaker metrics
     */
    public CircuitBreakerMetrics getMetrics(String name) {
        CircuitBreaker circuitBreaker = circuitBreakers.get(name);
        if (circuitBreaker == null) {
            return null;
        }

        CircuitBreaker.Metrics metrics = circuitBreaker.getMetrics();
        return CircuitBreakerMetrics.builder()
            .name(name)
            .state(circuitBreaker.getState().toString())
            .failureRate(metrics.getFailureRate())
            .slowCallRate(metrics.getSlowCallRate())
            .numberOfBufferedCalls(metrics.getNumberOfBufferedCalls())
            .numberOfFailedCalls(metrics.getNumberOfFailedCalls())
            .numberOfSlowCalls(metrics.getNumberOfSlowCalls())
            .numberOfSuccessfulCalls(metrics.getNumberOfSuccessfulCalls())
            .build();
    }

    @Data
    public static class Config {
        private String name = "default";
        private float failureRateThreshold = 50.0f;
        private Duration waitDurationInOpenState = Duration.ofSeconds(60);
        private int permittedNumberOfCallsInHalfOpenState = 10;
        private int slidingWindowSize = 100;
        private CircuitBreakerConfig.SlidingWindowType slidingWindowType = CircuitBreakerConfig.SlidingWindowType.COUNT_BASED;
        private int minimumNumberOfCalls = 10;
        private Duration slowCallDuration = Duration.ofSeconds(3);
        private float slowCallRateThreshold = 50.0f;
        private boolean automaticTransitionEnabled = true;
        private String fallbackUri;
        private Class<? extends Throwable>[] ignoreExceptions = new Class[0];
    }

    @Data
    @lombok.Builder
    public static class CircuitBreakerMetrics {
        private String name;
        private String state;
        private float failureRate;
        private float slowCallRate;
        private int numberOfBufferedCalls;
        private int numberOfFailedCalls;
        private int numberOfSlowCalls;
        private int numberOfSuccessfulCalls;
    }
}