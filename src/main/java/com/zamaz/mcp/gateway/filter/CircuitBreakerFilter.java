package com.zamaz.mcp.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Circuit breaker filter to prevent cascading failures.
 * Monitors backend service health and temporarily blocks requests to failing services.
 */
@Component
@Order(3)
@RequiredArgsConstructor
@Slf4j
public class CircuitBreakerFilter extends OncePerRequestFilter {

    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;

    @Value("${circuit-breaker.enabled:true}")
    private boolean circuitBreakerEnabled;

    @Value("${circuit-breaker.failure-threshold:5}")
    private int failureThreshold;

    @Value("${circuit-breaker.success-threshold:3}")
    private int successThreshold;

    @Value("${circuit-breaker.timeout:30000}") // 30 seconds
    private long timeout;

    @Value("${circuit-breaker.half-open-requests:3}")
    private int halfOpenRequests;

    private static final String CIRCUIT_PREFIX = "circuit:";
    private static final String FAILURE_COUNT_PREFIX = "circuit:failures:";
    private static final String SUCCESS_COUNT_PREFIX = "circuit:success:";
    private static final String HALF_OPEN_COUNT_PREFIX = "circuit:halfopen:";

    private enum CircuitState {
        CLOSED,     // Normal operation
        OPEN,       // Blocking requests
        HALF_OPEN   // Testing if service recovered
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException {
        
        if (!circuitBreakerEnabled) {
            filterChain.doFilter(request, response);
            return;
        }

        String serviceId = getServiceId(request);
        if (serviceId == null) {
            filterChain.doFilter(request, response);
            return;
        }

        CircuitState state = getCircuitState(serviceId);
        
        switch (state) {
            case OPEN:
                // Circuit is open, reject request
                rejectRequest(response, serviceId);
                return;
                
            case HALF_OPEN:
                // Allow limited requests through
                if (!allowHalfOpenRequest(serviceId)) {
                    rejectRequest(response, serviceId);
                    return;
                }
                break;
                
            case CLOSED:
                // Normal operation
                break;
        }

        // Execute request and monitor result
        long startTime = System.currentTimeMillis();
        boolean success = false;
        
        try {
            filterChain.doFilter(request, response);
            
            // Check if response indicates success
            int status = response.getStatus();
            success = status >= 200 && status < 500; // Client errors don't count as circuit failures
            
            if (!success) {
                recordFailure(serviceId);
            } else {
                recordSuccess(serviceId, state);
            }
            
        } catch (Exception e) {
            recordFailure(serviceId);
            throw e;
        } finally {
            // Record metrics
            long duration = System.currentTimeMillis() - startTime;
            recordMetrics(serviceId, success, duration);
        }
    }

    /**
     * Get service ID from request path.
     */
    private String getServiceId(HttpServletRequest request) {
        String path = request.getRequestURI();
        
        // Extract service from path (e.g., /api/v1/organization/... -> organization)
        if (path.startsWith("/api/v1/")) {
            String[] parts = path.substring(8).split("/");
            if (parts.length > 0) {
                return parts[0];
            }
        }
        
        return null;
    }

    /**
     * Get current circuit state for a service.
     */
    private CircuitState getCircuitState(String serviceId) {
        String stateKey = CIRCUIT_PREFIX + serviceId + ":state";
        String state = redisTemplate.opsForValue().get(stateKey);
        
        if (state == null) {
            return CircuitState.CLOSED;
        }
        
        try {
            return CircuitState.valueOf(state);
        } catch (IllegalArgumentException e) {
            return CircuitState.CLOSED;
        }
    }

    /**
     * Set circuit state for a service.
     */
    private void setCircuitState(String serviceId, CircuitState state, Duration duration) {
        String stateKey = CIRCUIT_PREFIX + serviceId + ":state";
        
        if (state == CircuitState.CLOSED) {
            redisTemplate.delete(stateKey);
        } else {
            redisTemplate.opsForValue().set(stateKey, state.toString(), duration);
        }
        
        log.info("Circuit breaker for service {} changed to {}", serviceId, state);
    }

    /**
     * Record a failure for the service.
     */
    private void recordFailure(String serviceId) {
        String failureKey = FAILURE_COUNT_PREFIX + serviceId;
        Long failures = redisTemplate.opsForValue().increment(failureKey);
        
        if (failures == 1) {
            redisTemplate.expire(failureKey, 1, TimeUnit.MINUTES);
        }
        
        // Check if we should open the circuit
        if (failures >= failureThreshold) {
            CircuitState currentState = getCircuitState(serviceId);
            if (currentState != CircuitState.OPEN) {
                openCircuit(serviceId);
            }
        }
        
        log.debug("Recorded failure for service {}, total failures: {}", serviceId, failures);
    }

    /**
     * Record a success for the service.
     */
    private void recordSuccess(String serviceId, CircuitState currentState) {
        if (currentState == CircuitState.HALF_OPEN) {
            String successKey = SUCCESS_COUNT_PREFIX + serviceId;
            Long successes = redisTemplate.opsForValue().increment(successKey);
            
            if (successes == 1) {
                redisTemplate.expire(successKey, 1, TimeUnit.MINUTES);
            }
            
            // Check if we should close the circuit
            if (successes >= successThreshold) {
                closeCircuit(serviceId);
            }
        }
        
        // Reset failure count on success in closed state
        if (currentState == CircuitState.CLOSED) {
            String failureKey = FAILURE_COUNT_PREFIX + serviceId;
            redisTemplate.delete(failureKey);
        }
    }

    /**
     * Open the circuit breaker.
     */
    private void openCircuit(String serviceId) {
        setCircuitState(serviceId, CircuitState.OPEN, Duration.ofMillis(timeout));
        
        // Clear counters
        redisTemplate.delete(FAILURE_COUNT_PREFIX + serviceId);
        redisTemplate.delete(SUCCESS_COUNT_PREFIX + serviceId);
        
        // Schedule transition to half-open
        scheduleHalfOpen(serviceId);
        
        log.warn("Circuit breaker OPENED for service: {}", serviceId);
    }

    /**
     * Close the circuit breaker.
     */
    private void closeCircuit(String serviceId) {
        setCircuitState(serviceId, CircuitState.CLOSED, null);
        
        // Clear all counters
        redisTemplate.delete(FAILURE_COUNT_PREFIX + serviceId);
        redisTemplate.delete(SUCCESS_COUNT_PREFIX + serviceId);
        redisTemplate.delete(HALF_OPEN_COUNT_PREFIX + serviceId);
        
        log.info("Circuit breaker CLOSED for service: {}", serviceId);
    }

    /**
     * Schedule transition to half-open state.
     */
    private void scheduleHalfOpen(String serviceId) {
        // In a real implementation, this would use a scheduled task
        // For now, the timeout on the OPEN state will handle it
        String halfOpenKey = CIRCUIT_PREFIX + serviceId + ":halfopen";
        redisTemplate.opsForValue().set(halfOpenKey, "scheduled", timeout, TimeUnit.MILLISECONDS);
    }

    /**
     * Check if we should allow a request in half-open state.
     */
    private boolean allowHalfOpenRequest(String serviceId) {
        String countKey = HALF_OPEN_COUNT_PREFIX + serviceId;
        Long count = redisTemplate.opsForValue().increment(countKey);
        
        if (count == 1) {
            redisTemplate.expire(countKey, 10, TimeUnit.SECONDS);
            
            // Transition to half-open if we were open and timeout has passed
            CircuitState state = getCircuitState(serviceId);
            if (state == CircuitState.OPEN) {
                setCircuitState(serviceId, CircuitState.HALF_OPEN, Duration.ofMinutes(1));
            }
        }
        
        return count <= halfOpenRequests;
    }

    /**
     * Reject request due to open circuit.
     */
    private void rejectRequest(HttpServletResponse response, String serviceId) throws IOException {
        response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader("Retry-After", String.valueOf(timeout / 1000));
        
        Map<String, Object> error = new HashMap<>();
        error.put("error", "Service Unavailable");
        error.put("message", "Service " + serviceId + " is temporarily unavailable");
        error.put("retryAfter", timeout / 1000);
        
        response.getWriter().write(objectMapper.writeValueAsString(error));
        
        log.debug("Request rejected by circuit breaker for service: {}", serviceId);
    }

    /**
     * Record metrics for monitoring.
     */
    private void recordMetrics(String serviceId, boolean success, long duration) {
        // In a real implementation, this would send metrics to monitoring system
        String metricsKey = "metrics:circuit:" + serviceId;
        Map<String, String> metrics = new HashMap<>();
        metrics.put("lastRequest", String.valueOf(System.currentTimeMillis()));
        metrics.put("lastDuration", String.valueOf(duration));
        metrics.put("lastSuccess", String.valueOf(success));
        
        redisTemplate.opsForHash().putAll(metricsKey, metrics);
        redisTemplate.expire(metricsKey, 1, TimeUnit.HOURS);
    }
}