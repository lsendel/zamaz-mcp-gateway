package com.zamaz.mcp.gateway.config;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.support.ipresolver.XForwardedRemoteAddressResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * WebSocket proxy configuration and connection management
 */
@Configuration
@Slf4j
public class WebSocketProxyConfig {
    
    @Value("${websocket.max-connections-per-ip:10}")
    private int maxConnectionsPerIp;
    
    @Value("${websocket.max-frame-size:65536}")
    private int maxFrameSize;
    
    @Value("${websocket.idle-timeout:300000}")
    private long idleTimeout;
    
    @Autowired(required = false)
    private MeterRegistry meterRegistry;
    
    private final ConcurrentHashMap<String, AtomicInteger> connectionCounts = new ConcurrentHashMap<>();
    
    // Metrics tracking
    private final AtomicLong activeConnections = new AtomicLong(0);
    private final AtomicLong totalConnections = new AtomicLong(0);
    private final AtomicLong failedConnections = new AtomicLong(0);
    private final Map<String, Timer> pathTimers = new ConcurrentHashMap<>();
    private final Map<String, Counter> pathCounters = new ConcurrentHashMap<>();
    private final Map<String, Counter> errorCounters = new ConcurrentHashMap<>();
    
    /**
     * WebSocket connection limit filter
     */
    @Bean
    public WebFilter webSocketConnectionLimitFilter() {
        return (ServerWebExchange exchange, WebFilterChain chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            
            // Only apply to WebSocket upgrade requests
            if (!isWebSocketUpgradeRequest(request)) {
                return chain.filter(exchange);
            }
            
            String clientIp = getClientIp(exchange);
            AtomicInteger count = connectionCounts.computeIfAbsent(clientIp, k -> new AtomicInteger(0));
            
            if (count.get() >= maxConnectionsPerIp) {
                log.warn("WebSocket connection limit exceeded for IP: {}", clientIp);
                exchange.getResponse().setRawStatusCode(429);
                return exchange.getResponse().setComplete();
            }
            
            count.incrementAndGet();
            log.debug("WebSocket connection opened from IP: {} (count: {})", clientIp, count.get());
            
            return chain.filter(exchange)
                .doFinally(signal -> {
                    int newCount = count.decrementAndGet();
                    log.debug("WebSocket connection closed from IP: {} (count: {})", clientIp, newCount);
                    
                    // Clean up if no more connections
                    if (newCount == 0) {
                        connectionCounts.remove(clientIp);
                    }
                });
        };
    }
    
    /**
     * WebSocket metrics filter
     */
    @Bean
    public WebFilter webSocketMetricsFilter() {
        return (ServerWebExchange exchange, WebFilterChain chain) -> {
            if (!isWebSocketUpgradeRequest(exchange.getRequest())) {
                return chain.filter(exchange);
            }
            
            long startTime = System.currentTimeMillis();
            String path = exchange.getRequest().getPath().value();
            
            return chain.filter(exchange)
                .doOnSuccess(aVoid -> {
                    long duration = System.currentTimeMillis() - startTime;
                    log.info("WebSocket connection established: {} in {}ms", path, duration);
                    
                    // Send metrics to monitoring system
                    if (meterRegistry != null) {
                        activeConnections.incrementAndGet();
                        totalConnections.incrementAndGet();
                        
                        // Record path-specific metrics
                        getOrCreatePathCounter(path + ".success").increment();
                        getOrCreatePathTimer(path).record(duration, java.util.concurrent.TimeUnit.MILLISECONDS);
                        
                        // Update gauges
                        meterRegistry.gauge("websocket.connections.active", activeConnections);
                        meterRegistry.gauge("websocket.connections.total", totalConnections);
                    }
                })
                .doOnError(error -> {
                    log.error("WebSocket connection failed: {} - {}", path, error.getMessage());
                    
                    // Send error metrics
                    if (meterRegistry != null) {
                        failedConnections.incrementAndGet();
                        
                        // Record error metrics
                        getOrCreatePathCounter(path + ".error").increment();
                        getOrCreateErrorCounter(error.getClass().getSimpleName()).increment();
                        
                        // Update gauges
                        meterRegistry.gauge("websocket.connections.failed", failedConnections);
                    }
                })
                .doFinally(signalType -> {
                    // Decrement active connections when connection closes
                    if (meterRegistry != null) {
                        activeConnections.decrementAndGet();
                    }
                });
        };
    }
    
    /**
     * WebSocket security headers filter
     */
    @Bean
    public WebFilter webSocketSecurityHeadersFilter() {
        return (ServerWebExchange exchange, WebFilterChain chain) -> {
            if (!isWebSocketUpgradeRequest(exchange.getRequest())) {
                return chain.filter(exchange);
            }
            
            exchange.getResponse().getHeaders().add("X-Frame-Options", "DENY");
            exchange.getResponse().getHeaders().add("X-Content-Type-Options", "nosniff");
            exchange.getResponse().getHeaders().add("X-XSS-Protection", "1; mode=block");
            
            return chain.filter(exchange);
        };
    }
    
    /**
     * Remote address resolver for getting real client IP
     */
    @Bean
    public XForwardedRemoteAddressResolver remoteAddressResolver() {
        return XForwardedRemoteAddressResolver.maxTrustedIndex(1);
    }
    
    /**
     * Check if request is a WebSocket upgrade request
     */
    private boolean isWebSocketUpgradeRequest(ServerHttpRequest request) {
        String upgrade = request.getHeaders().getFirst("Upgrade");
        String connection = request.getHeaders().getFirst("Connection");
        
        return "websocket".equalsIgnoreCase(upgrade) && 
               connection != null && connection.toLowerCase().contains("upgrade");
    }
    
    /**
     * Get client IP address considering proxies
     */
    private String getClientIp(ServerWebExchange exchange) {
        XForwardedRemoteAddressResolver resolver = XForwardedRemoteAddressResolver.maxTrustedIndex(1);
        InetSocketAddress remoteAddress = resolver.resolve(exchange);
        
        if (remoteAddress != null && remoteAddress.getAddress() != null) {
            return remoteAddress.getAddress().getHostAddress();
        }
        
        // Fallback to direct connection IP
        InetSocketAddress directAddress = exchange.getRequest().getRemoteAddress();
        if (directAddress != null && directAddress.getAddress() != null) {
            return directAddress.getAddress().getHostAddress();
        }
        
        return "unknown";
    }
    
    /**
     * WebSocket connection statistics
     */
    @Bean
    public WebSocketConnectionStats webSocketConnectionStats() {
        return new WebSocketConnectionStats();
    }
    
    public class WebSocketConnectionStats {
        public int getTotalConnections() {
            return connectionCounts.values().stream()
                .mapToInt(AtomicInteger::get)
                .sum();
        }
        
        public int getUniqueIps() {
            return connectionCounts.size();
        }
        
        public ConcurrentHashMap<String, AtomicInteger> getConnectionsByIp() {
            return new ConcurrentHashMap<>(connectionCounts);
        }
    }
    
    /**
     * Get or create a path-specific counter
     */
    private Counter getOrCreatePathCounter(String path) {
        return pathCounters.computeIfAbsent(path, p -> 
            Counter.builder("websocket.path.requests")
                .tag("path", sanitizePath(p))
                .description("WebSocket path request counter")
                .register(meterRegistry));
    }
    
    /**
     * Get or create a path-specific timer
     */
    private Timer getOrCreatePathTimer(String path) {
        return pathTimers.computeIfAbsent(path, p -> 
            Timer.builder("websocket.path.duration")
                .tag("path", sanitizePath(p))
                .description("WebSocket path connection duration")
                .register(meterRegistry));
    }
    
    /**
     * Get or create an error counter
     */
    private Counter getOrCreateErrorCounter(String errorType) {
        return errorCounters.computeIfAbsent(errorType, e -> 
            Counter.builder("websocket.errors")
                .tag("error_type", e)
                .description("WebSocket error counter")
                .register(meterRegistry));
    }
    
    /**
     * Sanitize path for use as a metric tag
     */
    private String sanitizePath(String path) {
        // Remove dynamic parts from path for consistent tagging
        return path.replaceAll("/[0-9a-f-]+", "/{id}")
                   .replaceAll("\\.", "_")
                   .replaceAll("/", "_");
    }
}