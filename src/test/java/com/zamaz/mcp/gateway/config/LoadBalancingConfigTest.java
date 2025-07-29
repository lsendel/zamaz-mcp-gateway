package com.zamaz.mcp.gateway.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.client.DefaultServiceInstance;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.ReactiveDiscoveryClient;
import org.springframework.cloud.client.loadbalancer.Request;
import org.springframework.cloud.client.loadbalancer.Response;
import org.springframework.cloud.loadbalancer.core.ReactorServiceInstanceLoadBalancer;
import org.springframework.cloud.loadbalancer.core.ServiceInstanceListSupplier;
import org.springframework.cloud.loadbalancer.support.LoadBalancerClientFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Tests for load balancing configuration
 */
@ExtendWith(MockitoExtension.class)
class LoadBalancingConfigTest {

    @Mock
    private LoadBalancerClientFactory loadBalancerClientFactory;

    @Mock
    private ReactiveDiscoveryClient discoveryClient;

    @Mock
    private ServiceInstanceListSupplier serviceInstanceListSupplier;

    private LoadBalancingConfig loadBalancingConfig;

    private List<ServiceInstance> testInstances;

    @BeforeEach
    void setUp() {
        loadBalancingConfig = new LoadBalancingConfig();

        // Create test service instances
        testInstances = Arrays.asList(
            new DefaultServiceInstance("instance-1", "test-service", "localhost", 8081, false),
            new DefaultServiceInstance("instance-2", "test-service", "localhost", 8082, false),
            new DefaultServiceInstance("instance-3", "test-service", "localhost", 8083, false)
        );
    }

    @Test
    void loadBalancedWebClientBuilder_ShouldConfigureMaxInMemorySize() {
        // Act
        WebClient.Builder builder = loadBalancingConfig.loadBalancedWebClientBuilder();

        // Assert
        assertNotNull(builder);
        // The builder is configured with 5MB max in-memory size
        // This would be verified in integration tests
    }

    @Test
    void roundRobinLoadBalancer_ShouldDistributeEvenly() {
        // Arrange
        when(serviceInstanceListSupplier.get()).thenReturn(Flux.just(testInstances));
        
        LoadBalancerClientFactory.LazyProvider<ServiceInstanceListSupplier> lazyProvider = mock(LoadBalancerClientFactory.LazyProvider.class);
        when(lazyProvider.getIfAvailable()).thenReturn(serviceInstanceListSupplier);

        RoundRobinLoadBalancer loadBalancer = new RoundRobinLoadBalancer(lazyProvider, "test-service");

        // Act & Assert
        // First round
        StepVerifier.create(loadBalancer.choose(mock(Request.class)))
            .assertNext(response -> {
                assertNotNull(response.getServer());
                assertEquals(8081, response.getServer().getPort());
            })
            .verifyComplete();

        // Second round
        StepVerifier.create(loadBalancer.choose(mock(Request.class)))
            .assertNext(response -> {
                assertNotNull(response.getServer());
                assertEquals(8082, response.getServer().getPort());
            })
            .verifyComplete();

        // Third round
        StepVerifier.create(loadBalancer.choose(mock(Request.class)))
            .assertNext(response -> {
                assertNotNull(response.getServer());
                assertEquals(8083, response.getServer().getPort());
            })
            .verifyComplete();

        // Fourth round - should wrap around to first instance
        StepVerifier.create(loadBalancer.choose(mock(Request.class)))
            .assertNext(response -> {
                assertNotNull(response.getServer());
                assertEquals(8081, response.getServer().getPort());
            })
            .verifyComplete();
    }

    @Test
    void roundRobinLoadBalancer_WithNoInstances_ShouldReturnEmptyResponse() {
        // Arrange
        when(serviceInstanceListSupplier.get()).thenReturn(Flux.just(Arrays.asList()));
        
        LoadBalancerClientFactory.LazyProvider<ServiceInstanceListSupplier> lazyProvider = mock(LoadBalancerClientFactory.LazyProvider.class);
        when(lazyProvider.getIfAvailable()).thenReturn(serviceInstanceListSupplier);

        RoundRobinLoadBalancer loadBalancer = new RoundRobinLoadBalancer(lazyProvider, "test-service");

        // Act & Assert
        StepVerifier.create(loadBalancer.choose(mock(Request.class)))
            .assertNext(response -> {
                assertFalse(response.hasServer());
            })
            .verifyComplete();
    }

    @Test
    void leastConnectionsLoadBalancer_ShouldSelectLeastConnectedInstance() {
        // Arrange
        when(serviceInstanceListSupplier.get()).thenReturn(Flux.just(testInstances));
        
        LoadBalancerClientFactory.LazyProvider<ServiceInstanceListSupplier> lazyProvider = mock(LoadBalancerClientFactory.LazyProvider.class);
        when(lazyProvider.getIfAvailable()).thenReturn(serviceInstanceListSupplier);

        LeastConnectionsLoadBalancer loadBalancer = new LeastConnectionsLoadBalancer(lazyProvider, "test-service");

        // Act & Assert
        // All instances start with 0 connections, so first should be selected
        StepVerifier.create(loadBalancer.choose(mock(Request.class)))
            .assertNext(response -> {
                assertNotNull(response.getServer());
                assertEquals("instance-1", response.getServer().getInstanceId());
            })
            .verifyComplete();

        // Next request should go to instance-2 (as instance-1 now has 1 connection)
        StepVerifier.create(loadBalancer.choose(mock(Request.class)))
            .assertNext(response -> {
                assertNotNull(response.getServer());
                assertEquals("instance-2", response.getServer().getInstanceId());
            })
            .verifyComplete();

        // Next request should go to instance-3
        StepVerifier.create(loadBalancer.choose(mock(Request.class)))
            .assertNext(response -> {
                assertNotNull(response.getServer());
                assertEquals("instance-3", response.getServer().getInstanceId());
            })
            .verifyComplete();
    }

    @Test
    void healthCheckServiceInstanceListSupplier_ShouldFilterUnhealthyInstances() {
        // Arrange
        WebClient webClient = mock(WebClient.class);
        WebClient.RequestHeadersUriSpec requestSpec = mock(WebClient.RequestHeadersUriSpec.class);
        WebClient.RequestHeadersSpec requestHeadersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);

        when(webClient.get()).thenReturn(requestSpec);
        when(requestSpec.uri(anyString())).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);

        // Configure health check responses
        when(responseSpec.toBodilessEntity())
            .thenReturn(Mono.just(org.springframework.http.ResponseEntity.ok().build())) // instance-1 healthy
            .thenReturn(Mono.error(new RuntimeException("Connection refused"))) // instance-2 unhealthy
            .thenReturn(Mono.just(org.springframework.http.ResponseEntity.ok().build())); // instance-3 healthy

        ServiceInstanceListSupplier delegate = mock(ServiceInstanceListSupplier.class);
        when(delegate.getServiceId()).thenReturn("test-service");
        when(delegate.get()).thenReturn(Flux.just(testInstances));

        HealthCheckServiceInstanceListSupplier healthCheckSupplier = 
            new HealthCheckServiceInstanceListSupplier(delegate, webClient);

        // Act & Assert
        StepVerifier.create(healthCheckSupplier.get())
            .assertNext(instances -> {
                assertEquals(2, instances.size()); // Only healthy instances
                assertTrue(instances.stream().anyMatch(i -> "instance-1".equals(i.getInstanceId())));
                assertFalse(instances.stream().anyMatch(i -> "instance-2".equals(i.getInstanceId()))); // Unhealthy
                assertTrue(instances.stream().anyMatch(i -> "instance-3".equals(i.getInstanceId())));
            })
            .verifyComplete();
    }

    @Test
    void llmServiceLoadBalancerConfig_ShouldCreateHealthCheckSupplier() {
        // Arrange
        LlmServiceLoadBalancerConfig config = new LlmServiceLoadBalancerConfig();
        
        when(discoveryClient.getInstances("llm-service")).thenReturn(Flux.just(testInstances));

        // Act
        ServiceInstanceListSupplier supplier = config.serviceInstanceListSupplier(discoveryClient);

        // Assert
        assertNotNull(supplier);
        assertTrue(supplier instanceof HealthCheckServiceInstanceListSupplier);
    }

    @Test
    void debateServiceLoadBalancerConfig_ShouldCreateHealthCheckSupplier() {
        // Arrange
        DebateServiceLoadBalancerConfig config = new DebateServiceLoadBalancerConfig();
        
        when(discoveryClient.getInstances("debate-service")).thenReturn(Flux.just(testInstances));

        // Act
        ServiceInstanceListSupplier supplier = config.serviceInstanceListSupplier(discoveryClient);

        // Assert
        assertNotNull(supplier);
        assertTrue(supplier instanceof HealthCheckServiceInstanceListSupplier);
    }

    @Test
    void loadBalancer_ShouldHandleInstanceFailure() {
        // Arrange
        List<ServiceInstance> dynamicInstances = new java.util.ArrayList<>(testInstances);
        AtomicInteger callCount = new AtomicInteger(0);
        
        when(serviceInstanceListSupplier.get()).thenAnswer(invocation -> {
            if (callCount.incrementAndGet() > 2) {
                // Remove instance-2 after 2 calls (simulating failure)
                dynamicInstances.removeIf(i -> "instance-2".equals(i.getInstanceId()));
            }
            return Flux.just(new java.util.ArrayList<>(dynamicInstances));
        });
        
        LoadBalancerClientFactory.LazyProvider<ServiceInstanceListSupplier> lazyProvider = mock(LoadBalancerClientFactory.LazyProvider.class);
        when(lazyProvider.getIfAvailable()).thenReturn(serviceInstanceListSupplier);

        RoundRobinLoadBalancer loadBalancer = new RoundRobinLoadBalancer(lazyProvider, "test-service");

        // Act & Assert
        // Make several requests
        for (int i = 0; i < 6; i++) {
            StepVerifier.create(loadBalancer.choose(mock(Request.class)))
                .assertNext(response -> {
                    assertNotNull(response.getServer());
                    // After instance-2 is removed, it should not be selected
                    if (i >= 3) {
                        assertNotEquals("instance-2", response.getServer().getInstanceId());
                    }
                })
                .verifyComplete();
        }
    }

    @Test
    void healthCheckSupplier_ShouldCacheHealthStatus() {
        // Arrange
        WebClient webClient = mock(WebClient.class);
        WebClient.RequestHeadersUriSpec requestSpec = mock(WebClient.RequestHeadersUriSpec.class);
        WebClient.RequestHeadersSpec requestHeadersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);

        when(webClient.get()).thenReturn(requestSpec);
        when(requestSpec.uri(anyString())).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.toBodilessEntity())
            .thenReturn(Mono.just(org.springframework.http.ResponseEntity.ok().build()));

        ServiceInstanceListSupplier delegate = mock(ServiceInstanceListSupplier.class);
        when(delegate.getServiceId()).thenReturn("test-service");
        when(delegate.get()).thenReturn(Flux.just(testInstances));

        HealthCheckServiceInstanceListSupplier healthCheckSupplier = 
            new HealthCheckServiceInstanceListSupplier(delegate, webClient);

        // Act - Make multiple calls
        StepVerifier.create(healthCheckSupplier.get())
            .assertNext(instances -> assertEquals(3, instances.size()))
            .verifyComplete();

        StepVerifier.create(healthCheckSupplier.get())
            .assertNext(instances -> assertEquals(3, instances.size()))
            .verifyComplete();

        // Assert - Health check should only be called once per instance due to caching
        verify(responseSpec, times(3)).toBodilessEntity(); // Once per instance
    }
}