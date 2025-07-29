package com.zamaz.mcp.gateway.health;

import com.zamaz.mcp.gateway.config.WebSocketProxyConfig.WebSocketConnectionStats;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * Health indicator for WebSocket connections
 */
@Component
public class WebSocketHealthIndicator implements HealthIndicator {
    
    @Autowired
    private WebSocketConnectionStats connectionStats;
    
    @Value("${websocket.max-connections-per-ip:10}")
    private int maxConnectionsPerIp;
    
    @Value("${websocket.health.max-total-connections:1000}")
    private int maxTotalConnections;
    
    @Value("${websocket.health.warning-threshold:0.8}")
    private double warningThreshold;
    
    @Override
    public Health health() {
        try {
            int totalConnections = connectionStats.getTotalConnections();
            int uniqueIps = connectionStats.getUniqueIps();
            
            Health.Builder builder = Health.up()
                .withDetail("totalConnections", totalConnections)
                .withDetail("uniqueIPs", uniqueIps)
                .withDetail("maxConnectionsPerIP", maxConnectionsPerIp)
                .withDetail("maxTotalConnections", maxTotalConnections);
            
            // Check if we're approaching connection limits
            double utilizationRate = (double) totalConnections / maxTotalConnections;
            builder.withDetail("utilizationRate", String.format("%.2f%%", utilizationRate * 100));
            
            // Add top connected IPs for monitoring
            connectionStats.getConnectionsByIp().entrySet().stream()
                .sorted((e1, e2) -> Integer.compare(
                    e2.getValue().get(), e1.getValue().get()))
                .limit(5)
                .forEach(entry -> 
                    builder.withDetail("topIP_" + entry.getKey(), 
                        entry.getValue().get() + " connections"));
            
            // Set health status based on utilization
            if (utilizationRate > warningThreshold) {
                builder.status(Health.down().getStatus())
                    .withDetail("warning", "High connection utilization");
            } else if (utilizationRate > (warningThreshold * 0.8)) {
                builder.withDetail("info", "Approaching connection limit");
            }
            
            return builder.build();
            
        } catch (Exception e) {
            return Health.down()
                .withDetail("error", e.getMessage())
                .build();
        }
    }
}