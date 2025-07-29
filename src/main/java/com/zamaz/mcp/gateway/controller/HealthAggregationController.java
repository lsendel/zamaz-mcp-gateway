package com.zamaz.mcp.gateway.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.Status;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Health check aggregation controller that checks all downstream services
 */
@RestController
@RequestMapping("/health")
@RequiredArgsConstructor
@Slf4j
public class HealthAggregationController implements HealthIndicator {
    
    private final WebClient.Builder webClientBuilder;
    private final Map<String, ServiceHealth> serviceHealthCache = new ConcurrentHashMap<>();
    
    // Service endpoints
    private static final Map<String, String> SERVICE_ENDPOINTS = Map.of(
        "organization", "http://mcp-organization:5005/actuator/health",
        "llm", "http://mcp-llm:5002/actuator/health",
        "controller", "http://mcp-controller:5013/actuator/health",
        "rag", "http://mcp-rag:5004/actuator/health",
        "template", "http://mcp-template:5006/actuator/health"
    );
    
    @GetMapping(value = "/aggregate", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<Map<String, Object>> aggregateHealth() {
        log.debug("Aggregating health status from all services");
        
        // Check all services in parallel
        return Flux.fromIterable(SERVICE_ENDPOINTS.entrySet())
            .flatMap(entry -> checkServiceHealth(entry.getKey(), entry.getValue()))
            .collectMap(ServiceHealth::getName, health -> health)
            .map(this::buildAggregateResponse);
    }
    
    @GetMapping(value = "/services", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<Map<String, ServiceHealth>> getServicesHealth() {
        return Flux.fromIterable(SERVICE_ENDPOINTS.entrySet())
            .flatMap(entry -> checkServiceHealth(entry.getKey(), entry.getValue()))
            .collectMap(ServiceHealth::getName, health -> health);
    }
    
    private Mono<ServiceHealth> checkServiceHealth(String serviceName, String healthUrl) {
        WebClient webClient = webClientBuilder.build();
        
        return webClient.get()
            .uri(healthUrl)
            .retrieve()
            .bodyToMono(Map.class)
            .map(response -> {
                String status = (String) response.getOrDefault("status", "UNKNOWN");
                ServiceHealth health = new ServiceHealth(serviceName, status, response);
                serviceHealthCache.put(serviceName, health);
                return health;
            })
            .timeout(Duration.ofSeconds(2))
            .onErrorResume(error -> {
                log.warn("Health check failed for service {}: {}", serviceName, error.getMessage());
                ServiceHealth cachedHealth = serviceHealthCache.get(serviceName);
                if (cachedHealth != null) {
                    // Return cached status with degraded flag
                    return Mono.just(new ServiceHealth(serviceName, "DEGRADED", 
                        Map.of("cached", true, "error", error.getMessage())));
                }
                return Mono.just(new ServiceHealth(serviceName, "DOWN", 
                    Map.of("error", error.getMessage())));
            });
    }
    
    private Map<String, Object> buildAggregateResponse(Map<String, ServiceHealth> servicesHealth) {
        Map<String, Object> response = new HashMap<>();
        
        // Determine overall status
        boolean allHealthy = servicesHealth.values().stream()
            .allMatch(health -> "UP".equals(health.getStatus()));
        
        boolean anyDown = servicesHealth.values().stream()
            .anyMatch(health -> "DOWN".equals(health.getStatus()));
        
        String overallStatus = anyDown ? "DOWN" : (allHealthy ? "UP" : "DEGRADED");
        
        response.put("status", overallStatus);
        response.put("services", servicesHealth);
        response.put("timestamp", System.currentTimeMillis());
        
        // Add summary statistics
        Map<String, Long> statusCounts = new HashMap<>();
        servicesHealth.values().forEach(health -> 
            statusCounts.merge(health.getStatus(), 1L, Long::sum)
        );
        response.put("summary", statusCounts);
        
        return response;
    }
    
    @Override
    public Health health() {
        // Implementation for Spring Boot health indicator
        Map<String, ServiceHealth> servicesHealth = getServicesHealth()
            .block(Duration.ofSeconds(5));
        
        if (servicesHealth == null || servicesHealth.isEmpty()) {
            return Health.down()
                .withDetail("message", "Unable to check services health")
                .build();
        }
        
        boolean anyDown = servicesHealth.values().stream()
            .anyMatch(health -> "DOWN".equals(health.getStatus()));
        
        if (anyDown) {
            return Health.down()
                .withDetail("services", servicesHealth)
                .build();
        }
        
        boolean allHealthy = servicesHealth.values().stream()
            .allMatch(health -> "UP".equals(health.getStatus()));
        
        if (allHealthy) {
            return Health.up()
                .withDetail("services", servicesHealth)
                .build();
        }
        
        // Some services are degraded
        return Health.status("DEGRADED")
            .withDetail("services", servicesHealth)
            .build();
    }
    
    /**
     * Service health data class
     */
    public static class ServiceHealth {
        private final String name;
        private final String status;
        private final Map<String, Object> details;
        
        public ServiceHealth(String name, String status, Map<String, Object> details) {
            this.name = name;
            this.status = status;
            this.details = details;
        }
        
        public String getName() {
            return name;
        }
        
        public String getStatus() {
            return status;
        }
        
        public Map<String, Object> getDetails() {
            return details;
        }
    }
}