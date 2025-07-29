package com.zamaz.mcp.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 * Main application class for MCP API Gateway.
 * Provides unified entry point for all microservices with security,
 * rate limiting, and request routing capabilities.
 */
@SpringBootApplication
@EnableDiscoveryClient
@ConfigurationPropertiesScan
public class McpGatewayApplication {
    
    public static void main(String[] args) {
        SpringApplication.run(McpGatewayApplication.class, args);
    }
}