package com.zamaz.mcp.gateway.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.ReactiveDiscoveryClient;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.cloud.client.loadbalancer.reactive.ReactiveLoadBalancer;
import org.springframework.cloud.loadbalancer.annotation.LoadBalancerClient;
import org.springframework.cloud.loadbalancer.annotation.LoadBalancerClients;
import org.springframework.cloud.loadbalancer.core.ReactorServiceInstanceLoadBalancer;
import org.springframework.cloud.loadbalancer.core.ServiceInstanceListSupplier;
import org.springframework.cloud.loadbalancer.support.LoadBalancerClientFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Load balancing configuration for API Gateway
 */
@Configuration
@LoadBalancerClients({
    @LoadBalancerClient(name = "llm-service", configuration = LlmServiceLoadBalancerConfig.class),
    @LoadBalancerClient(name = "debate-service", configuration = DebateServiceLoadBalancerConfig.class)
})
@RequiredArgsConstructor
@Slf4j
public class LoadBalancingConfig {

    /**
     * Load balanced WebClient for inter-service communication
     */
    @Bean
    @LoadBalanced
    public WebClient.Builder loadBalancedWebClientBuilder() {
        return WebClient.builder()
            .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(1024 * 1024 * 5)); // 5MB
    }

    /**
     * Custom load balancer for LLM service with round-robin algorithm
     */
    @Bean
    @Primary
    public ReactorServiceInstanceLoadBalancer llmServiceLoadBalancer(
            LoadBalancerClientFactory loadBalancerClientFactory) {
        return new RoundRobinLoadBalancer(
            loadBalancerClientFactory.getLazyProvider("llm-service", ServiceInstanceListSupplier.class),
            "llm-service"
        );
    }

    /**
     * Custom load balancer for Debate service with least connections algorithm
     */
    @Bean
    public ReactorServiceInstanceLoadBalancer debateServiceLoadBalancer(
            LoadBalancerClientFactory loadBalancerClientFactory) {
        return new LeastConnectionsLoadBalancer(
            loadBalancerClientFactory.getLazyProvider("debate-service", ServiceInstanceListSupplier.class),
            "debate-service"
        );
    }
}

/**
 * Round-robin load balancer implementation
 */
@Slf4j
class RoundRobinLoadBalancer implements ReactorServiceInstanceLoadBalancer {

    private final AtomicInteger position = new AtomicInteger(0);
    private final String serviceId;
    private final org.springframework.cloud.context.config.annotation.RefreshScope.ScopedProxyMode serviceInstanceListSupplierProvider;

    public RoundRobinLoadBalancer(Object serviceInstanceListSupplierProvider, String serviceId) {
        this.serviceInstanceListSupplierProvider = (org.springframework.cloud.context.config.annotation.RefreshScope.ScopedProxyMode) serviceInstanceListSupplierProvider;
        this.serviceId = serviceId;
    }

    @Override
    public Mono<org.springframework.cloud.client.loadbalancer.Response<ServiceInstance>> choose(
            org.springframework.cloud.client.loadbalancer.Request request) {
        
        ServiceInstanceListSupplier supplier = ((org.springframework.cloud.loadbalancer.support.LoadBalancerClientFactory.LazyProvider<ServiceInstanceListSupplier>) serviceInstanceListSupplierProvider).getIfAvailable();
        
        return supplier.get().next()
            .map(instances -> {
                if (instances.isEmpty()) {
                    log.warn("No instances available for service: {}", serviceId);
                    return new org.springframework.cloud.client.loadbalancer.EmptyResponse();
                }
                
                int pos = Math.abs(position.incrementAndGet());
                ServiceInstance instance = instances.get(pos % instances.size());
                
                log.debug("Round-robin selected instance: {} for service: {}", 
                    instance.getUri(), serviceId);
                
                return new org.springframework.cloud.client.loadbalancer.DefaultResponse(instance);
            });
    }
}

/**
 * Least connections load balancer implementation
 */
@Slf4j
class LeastConnectionsLoadBalancer implements ReactorServiceInstanceLoadBalancer {

    private final Map<String, AtomicInteger> connectionCounts = new ConcurrentHashMap<>();
    private final String serviceId;
    private final Object serviceInstanceListSupplierProvider;

    public LeastConnectionsLoadBalancer(Object serviceInstanceListSupplierProvider, String serviceId) {
        this.serviceInstanceListSupplierProvider = serviceInstanceListSupplierProvider;
        this.serviceId = serviceId;
    }

    @Override
    public Mono<org.springframework.cloud.client.loadbalancer.Response<ServiceInstance>> choose(
            org.springframework.cloud.client.loadbalancer.Request request) {
        
        ServiceInstanceListSupplier supplier = ((org.springframework.cloud.loadbalancer.support.LoadBalancerClientFactory.LazyProvider<ServiceInstanceListSupplier>) serviceInstanceListSupplierProvider).getIfAvailable();
        
        return supplier.get().next()
            .map(instances -> {
                if (instances.isEmpty()) {
                    log.warn("No instances available for service: {}", serviceId);
                    return new org.springframework.cloud.client.loadbalancer.EmptyResponse();
                }
                
                // Find instance with least connections
                ServiceInstance selectedInstance = null;
                int minConnections = Integer.MAX_VALUE;
                
                for (ServiceInstance instance : instances) {
                    String instanceId = instance.getInstanceId();
                    int connections = connectionCounts.computeIfAbsent(instanceId, k -> new AtomicInteger(0)).get();
                    
                    if (connections < minConnections) {
                        minConnections = connections;
                        selectedInstance = instance;
                    }
                }
                
                if (selectedInstance != null) {
                    connectionCounts.get(selectedInstance.getInstanceId()).incrementAndGet();
                    
                    log.debug("Least connections selected instance: {} with {} connections for service: {}", 
                        selectedInstance.getUri(), minConnections, serviceId);
                    
                    // Decrement connection count after request completes
                    Mono.delay(Duration.ofSeconds(1))
                        .subscribe(l -> connectionCounts.get(selectedInstance.getInstanceId()).decrementAndGet());
                    
                    return new org.springframework.cloud.client.loadbalancer.DefaultResponse(selectedInstance);
                }
                
                return new org.springframework.cloud.client.loadbalancer.EmptyResponse();
            });
    }
}

/**
 * Load balancer configuration for LLM service
 */
@Configuration
class LlmServiceLoadBalancerConfig {

    @Bean
    public ServiceInstanceListSupplier serviceInstanceListSupplier(ReactiveDiscoveryClient discoveryClient) {
        return new HealthCheckServiceInstanceListSupplier(
            ServiceInstanceListSupplier.builder()
                .withDiscoveryClient(discoveryClient)
                .withServiceName("llm-service")
                .build(),
            WebClient.builder().build()
        );
    }
}

/**
 * Load balancer configuration for Debate service
 */
@Configuration
class DebateServiceLoadBalancerConfig {

    @Bean
    public ServiceInstanceListSupplier serviceInstanceListSupplier(ReactiveDiscoveryClient discoveryClient) {
        return new HealthCheckServiceInstanceListSupplier(
            ServiceInstanceListSupplier.builder()
                .withDiscoveryClient(discoveryClient)
                .withServiceName("debate-service")
                .build(),
            WebClient.builder().build()
        );
    }
}

/**
 * Health check service instance list supplier
 */
@Slf4j
class HealthCheckServiceInstanceListSupplier implements ServiceInstanceListSupplier {

    private final ServiceInstanceListSupplier delegate;
    private final WebClient webClient;
    private final Map<String, Boolean> healthStatus = new ConcurrentHashMap<>();

    public HealthCheckServiceInstanceListSupplier(ServiceInstanceListSupplier delegate, WebClient webClient) {
        this.delegate = delegate;
        this.webClient = webClient;
    }

    @Override
    public String getServiceId() {
        return delegate.getServiceId();
    }

    @Override
    public Flux<List<ServiceInstance>> get() {
        return delegate.get()
            .flatMap(instances -> {
                // Filter healthy instances
                return Flux.fromIterable(instances)
                    .filterWhen(this::isHealthy)
                    .collectList();
            });
    }

    private Mono<Boolean> isHealthy(ServiceInstance instance) {
        String healthUrl = instance.getUri() + "/actuator/health";
        String instanceId = instance.getInstanceId();
        
        // Check cached health status
        Boolean cachedStatus = healthStatus.get(instanceId);
        if (cachedStatus != null) {
            return Mono.just(cachedStatus);
        }
        
        // Perform health check
        return webClient.get()
            .uri(healthUrl)
            .retrieve()
            .toBodilessEntity()
            .map(response -> {
                boolean healthy = response.getStatusCode().is2xxSuccessful();
                healthStatus.put(instanceId, healthy);
                
                // Clear cache after 30 seconds
                Mono.delay(Duration.ofSeconds(30))
                    .subscribe(l -> healthStatus.remove(instanceId));
                
                if (!healthy) {
                    log.warn("Instance {} is unhealthy", instance.getUri());
                }
                
                return healthy;
            })
            .onErrorReturn(false);
    }
}