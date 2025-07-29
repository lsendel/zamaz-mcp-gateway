package com.zamaz.mcp.gateway.config;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.timelimiter.TimeLimiterConfig;
import io.github.resilience4j.timelimiter.TimeLimiterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4JCircuitBreakerFactory;
import org.springframework.cloud.circuitbreaker.resilience4j.Resilience4JConfigBuilder;
import org.springframework.cloud.client.circuitbreaker.Customizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * Circuit breaker configuration for resilience
 */
@Configuration
@Slf4j
public class CircuitBreakerConfig {
    
    /**
     * Customize circuit breaker factory with specific configurations
     */
    @Bean
    public Customizer<ReactiveResilience4JCircuitBreakerFactory> defaultCustomizer() {
        return factory -> factory.configureDefault(id -> new Resilience4JConfigBuilder(id)
                .circuitBreakerConfig(io.github.resilience4j.circuitbreaker.CircuitBreakerConfig.custom()
                        .slidingWindowSize(10)
                        .slidingWindowType(io.github.resilience4j.circuitbreaker.CircuitBreakerConfig.SlidingWindowType.TIME_BASED)
                        .minimumNumberOfCalls(5)
                        .permittedNumberOfCallsInHalfOpenState(3)
                        .automaticTransitionFromOpenToHalfOpenEnabled(true)
                        .waitDurationInOpenState(Duration.ofSeconds(5))
                        .failureRateThreshold(50)
                        .slowCallDurationThreshold(Duration.ofSeconds(2))
                        .slowCallRateThreshold(50)
                        .recordExceptions(Exception.class)
                        .ignoreExceptions(IllegalArgumentException.class, IllegalStateException.class)
                        .build())
                .timeLimiterConfig(TimeLimiterConfig.custom()
                        .timeoutDuration(Duration.ofSeconds(10))
                        .build())
                .build());
    }
    
    /**
     * Service-specific circuit breaker customizers
     */
    @Bean
    public Customizer<ReactiveResilience4JCircuitBreakerFactory> llmServiceCustomizer() {
        return factory -> factory.configure(builder -> builder
                .circuitBreakerConfig(io.github.resilience4j.circuitbreaker.CircuitBreakerConfig.custom()
                        .slidingWindowSize(5)
                        .minimumNumberOfCalls(3)
                        .waitDurationInOpenState(Duration.ofSeconds(10))
                        .slowCallDurationThreshold(Duration.ofSeconds(5))
                        .build())
                .timeLimiterConfig(TimeLimiterConfig.custom()
                        .timeoutDuration(Duration.ofSeconds(30)) // LLM calls can be slower
                        .build()), "llm-cb");
    }
    
    @Bean
    public Customizer<ReactiveResilience4JCircuitBreakerFactory> organizationServiceCustomizer() {
        return factory -> factory.configure(builder -> builder
                .circuitBreakerConfig(io.github.resilience4j.circuitbreaker.CircuitBreakerConfig.custom()
                        .slidingWindowSize(20)
                        .minimumNumberOfCalls(10)
                        .waitDurationInOpenState(Duration.ofSeconds(3))
                        .failureRateThreshold(30) // More lenient for auth service
                        .build())
                .timeLimiterConfig(TimeLimiterConfig.custom()
                        .timeoutDuration(Duration.ofSeconds(5))
                        .build()), "organization-cb");
    }
    
    /**
     * Circuit breaker event listeners for monitoring
     */
    @Bean
    public CircuitBreakerRegistry circuitBreakerRegistry() {
        CircuitBreakerRegistry registry = CircuitBreakerRegistry.ofDefaults();
        
        // Add event listeners for monitoring
        registry.getEventPublisher()
            .onEntryAdded(event -> {
                CircuitBreaker circuitBreaker = event.getAddedEntry();
                circuitBreaker.getEventPublisher()
                    .onStateTransition(e -> log.warn("Circuit breaker {} transitioned from {} to {}", 
                        circuitBreaker.getName(), e.getStateTransition().getFromState(), 
                        e.getStateTransition().getToState()))
                    .onSlowCallRateExceeded(e -> log.warn("Circuit breaker {} slow call rate exceeded: {}%", 
                        circuitBreaker.getName(), e.getSlowCallRate()))
                    .onFailureRateExceeded(e -> log.warn("Circuit breaker {} failure rate exceeded: {}%", 
                        circuitBreaker.getName(), e.getFailureRate()));
            });
        
        return registry;
    }
    
    /**
     * Time limiter registry for timeout handling
     */
    @Bean
    public TimeLimiterRegistry timeLimiterRegistry() {
        return TimeLimiterRegistry.ofDefaults();
    }
}