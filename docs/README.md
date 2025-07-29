# MCP-Gateway Service Documentation

The MCP-Gateway service provides a unified entry point for all API requests to the Zamaz Debate MCP system, handling routing, authentication, and cross-cutting concerns.

## Overview

The MCP-Gateway service acts as an API gateway for the entire MCP system. It routes requests to the appropriate microservices, handles authentication and authorization, implements rate limiting, and provides a consistent interface for clients. It serves as the primary entry point for all external API requests.

## Features

- **Request Routing**: Route requests to appropriate microservices
- **Authentication**: Validate API keys and JWT tokens
- **Authorization**: Enforce access control policies
- **Rate Limiting**: Protect services from excessive traffic
- **Request/Response Transformation**: Modify requests and responses as needed
- **Logging and Monitoring**: Track API usage and performance
- **Error Handling**: Provide consistent error responses
- **SSL Termination**: Handle HTTPS connections
- **API Documentation**: Expose OpenAPI documentation
- **Cross-Origin Resource Sharing (CORS)**: Manage CORS policies

## Architecture

The Gateway service is built using Spring Cloud Gateway and follows these architectural principles:

- **Route Definitions**: Configure service routes based on paths
- **Filter Chain**: Apply pre and post filters to requests
- **Circuit Breakers**: Handle service failures gracefully
- **Load Balancing**: Distribute traffic across service instances
- **Service Discovery**: Dynamically discover service instances

## API Endpoints

The Gateway exposes endpoints for all underlying services, with these additional endpoints:

### Gateway Management

- `GET /actuator/gateway/routes`: List all configured routes
- `POST /actuator/gateway/refresh`: Refresh route configurations
- `GET /actuator/health`: Gateway health status

### API Documentation

- `GET /api-docs`: OpenAPI documentation
- `GET /swagger-ui.html`: Swagger UI for API exploration

### Authentication

- `POST /api/v1/auth/login`: User login
- `POST /api/v1/auth/logout`: User logout
- `POST /api/v1/auth/refresh`: Refresh JWT token

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_PORT` | Server port | 8080 |
| `SECURITY_SERVICE_URL` | Security service URL | http://mcp-security:5007 |
| `ORGANIZATION_SERVICE_URL` | Organization service URL | http://mcp-organization:5005 |
| `LLM_SERVICE_URL` | LLM service URL | http://mcp-llm:5002 |
| `CONTROLLER_SERVICE_URL` | Controller service URL | http://mcp-controller:5013 |
| `RAG_SERVICE_URL` | RAG service URL | http://mcp-rag:5004 |
| `TEMPLATE_SERVICE_URL` | Template service URL | http://mcp-template:5006 |
| `CONTEXT_SERVICE_URL` | Context service URL | http://mcp-context:5001 |
| `REDIS_HOST` | Redis host | redis |
| `REDIS_PORT` | Redis port | 6379 |
| `JWT_SECRET` | Secret for JWT validation | your-256-bit-secret-key |
| `SSL_ENABLED` | Enable SSL | false |
| `SSL_CERT_PATH` | SSL certificate path | /certs/cert.pem |
| `SSL_KEY_PATH` | SSL key path | /certs/key.pem |
| `LOG_LEVEL` | Logging level | INFO |

### Gateway Configuration

Gateway-specific settings can be configured in `config/application.yml`:

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: organization-service
          uri: ${ORGANIZATION_SERVICE_URL}
          predicates:
            - Path=/api/v1/organizations/**
          filters:
            - AuthenticationFilter
            - RateLimiter=organization-rate-limiter
            
        - id: llm-service
          uri: ${LLM_SERVICE_URL}
          predicates:
            - Path=/api/v1/completions/**,/api/v1/models/**,/mcp/tools/complete
          filters:
            - AuthenticationFilter
            - RateLimiter=llm-rate-limiter
            
        - id: controller-service
          uri: ${CONTROLLER_SERVICE_URL}
          predicates:
            - Path=/api/v1/debates/**,/mcp/tools/create_debate
          filters:
            - AuthenticationFilter
            - RateLimiter=debate-rate-limiter
            
        - id: rag-service
          uri: ${RAG_SERVICE_URL}
          predicates:
            - Path=/api/v1/knowledge-bases/**,/api/v1/augment/**,/mcp/tools/search
          filters:
            - AuthenticationFilter
            - RateLimiter=rag-rate-limiter
            
        - id: template-service
          uri: ${TEMPLATE_SERVICE_URL}
          predicates:
            - Path=/api/v1/templates/**,/mcp/tools/create_template
          filters:
            - AuthenticationFilter
            - RateLimiter=template-rate-limiter
            
        - id: context-service
          uri: ${CONTEXT_SERVICE_URL}
          predicates:
            - Path=/api/v1/contexts/**,/mcp/tools/create_context
          filters:
            - AuthenticationFilter
            - RateLimiter=context-rate-limiter
            
      default-filters:
        - AddRequestHeader=X-Gateway-Timestamp,${now}
        - AddResponseHeader=X-Gateway-Version,1.0.0
        - Retry=3,500
        - CircuitBreaker=defaultCircuitBreaker
        - RequestRateLimiter=100,60,1
        - DedupeResponseHeader=Access-Control-Allow-Origin
        - DedupeResponseHeader=Access-Control-Allow-Credentials
        
  security:
    cors:
      allowed-origins: ${CORS_ALLOWED_ORIGINS:*}
      allowed-methods: GET,POST,PUT,DELETE,OPTIONS
      allowed-headers: Authorization,Content-Type,X-Organization-ID
      allow-credentials: true
      max-age: 3600
      
  redis:
    rate-limiter:
      repository-type: redis
      default-replenish-rate: 100
      default-burst-capacity: 200
```

## Usage Examples

### Accessing LLM Service via Gateway

```bash
curl -X POST http://localhost:8080/api/v1/completions \
  -H "Content-Type: application/json" \
  -H "X-Organization-ID: org-123" \
  -H "Authorization: Bearer your-jwt-token" \
  -d '{
    "model": "claude-3-opus-20240229",
    "prompt": "Explain quantum computing in simple terms",
    "maxTokens": 500,
    "temperature": 0.7
  }'
```

### Creating a Debate via Gateway

```bash
curl -X POST http://localhost:8080/api/v1/debates \
  -H "Content-Type: application/json" \
  -H "X-Organization-ID: org-123" \
  -H "Authorization: Bearer your-jwt-token" \
  -d '{
    "name": "Climate Policy Debate",
    "format": "oxford",
    "participants": [
      {
        "name": "Team Green",
        "role": "proposition",
        "llmConfig": {
          "provider": "claude",
          "model": "claude-3-opus-20240229",
          "systemPrompt": "You are an expert in environmental policy."
        }
      },
      {
        "name": "Team Growth", 
        "role": "opposition",
        "llmConfig": {
          "provider": "openai",
          "model": "gpt-4",
          "systemPrompt": "You are an economist focused on growth."
        }
      }
    ],
    "maxRounds": 6
  }'
```

### User Authentication via Gateway

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "your-secure-password"
  }'
```

## Gateway Filters

The Gateway implements several filters to process requests:

### Authentication Filter

Validates API keys and JWT tokens:

```java
public class AuthenticationFilter implements GatewayFilter {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Extract authentication token
        // Validate with Security service
        // Add user info to request context
        // Continue or reject request
    }
}
```

### Rate Limiting Filter

Implements rate limiting based on organization and endpoint:

```java
public class RateLimitingFilter implements GatewayFilter {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Extract organization ID
        // Check rate limit for organization
        // Allow or reject request
        // Update rate limit counters
    }
}
```

### Logging Filter

Logs request and response details:

```java
public class LoggingFilter implements GatewayFilter {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Log request details
        // Continue with request
        // Log response details
    }
}
```

### Error Handling Filter

Provides consistent error responses:

```java
public class ErrorHandlingFilter implements GatewayFilter {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Continue with request
        // Catch exceptions
        // Transform to standard error response
    }
}
```

## Route Configuration

Routes are configured to direct requests to the appropriate services:

### Route Definition

```java
@Configuration
public class RouteConfiguration {
    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
            .route("organization-service", r -> r
                .path("/api/v1/organizations/**")
                .filters(f -> f
                    .filter(authenticationFilter)
                    .filter(rateLimitingFilter)
                    .circuitBreaker(config -> config.setName("organizationCircuitBreaker"))
                )
                .uri("http://mcp-organization:5005")
            )
            // Additional routes
            .build();
    }
}
```

## Load Balancing

The Gateway implements load balancing for services with multiple instances:

```yaml
spring:
  cloud:
    loadbalancer:
      ribbon:
        enabled: false
      configurations:
        default:
          health-check:
            path: /actuator/health
            interval: 10s
          retry:
            max-retries-on-same-service-instance: 2
            max-retries-on-next-service-instance: 2
            retry-on-all-operations: false
```

## Circuit Breaker

The Gateway implements circuit breakers to handle service failures:

```yaml
resilience4j:
  circuitbreaker:
    configs:
      default:
        slidingWindowSize: 100
        permittedNumberOfCallsInHalfOpenState: 10
        waitDurationInOpenState: 10000
        failureRateThreshold: 50
        eventConsumerBufferSize: 100
    instances:
      organizationCircuitBreaker:
        baseConfig: default
      llmCircuitBreaker:
        baseConfig: default
```

## SSL Configuration

For production environments, SSL is configured:

```yaml
server:
  ssl:
    enabled: ${SSL_ENABLED:false}
    key-store: ${SSL_KEYSTORE_PATH:keystore.p12}
    key-store-password: ${SSL_KEYSTORE_PASSWORD:password}
    key-store-type: PKCS12
    key-alias: mcp-gateway
```

## CORS Configuration

Cross-Origin Resource Sharing is configured:

```yaml
spring:
  cloud:
    gateway:
      globalcors:
        corsConfigurations:
          '[/**]':
            allowedOrigins: ${CORS_ALLOWED_ORIGINS:*}
            allowedMethods: GET,POST,PUT,DELETE,OPTIONS
            allowedHeaders: Authorization,Content-Type,X-Organization-ID
            allowCredentials: true
            maxAge: 3600
```

## Monitoring and Metrics

The Gateway exposes the following metrics:

- Request count by service
- Response time by service
- Error rate by service
- Circuit breaker status
- Rate limit rejections
- Authentication failures

Access metrics at: `http://localhost:8080/actuator/metrics`

## Troubleshooting

### Common Issues

1. **Routing Issues**
   - Check route configuration
   - Verify service URLs are correct
   - Check service health status

2. **Authentication Issues**
   - Verify JWT token is valid
   - Check API key is correct
   - Ensure organization ID is included

3. **Rate Limiting Issues**
   - Check rate limit configuration
   - Monitor for unusual traffic patterns
   - Verify Redis connection for rate limit storage

### Logs

Gateway logs can be accessed via:

```bash
docker-compose logs mcp-gateway
```

## Development

### Building the Service

```bash
cd mcp-gateway
mvn clean install
```

### Running Tests

```bash
cd mcp-gateway
mvn test
```

### Local Development

```bash
cd mcp-gateway
mvn spring-boot:run
```

## Advanced Features

### Dynamic Route Configuration

Update routes without restarting the gateway:

```bash
curl -X POST http://localhost:8080/actuator/gateway/refresh \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin-token"
```

### Request Transformation

Transform requests before forwarding to services:

```bash
curl -X POST http://localhost:8080/api/v1/gateway/routes/llm-service/transforms \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin-token" \
  -d '{
    "requestTransforms": [
      {
        "path": "$.maxTokens",
        "operation": "max",
        "value": 4000
      }
    ]
  }'
```

### Traffic Shadowing

Shadow traffic to test new service versions:

```bash
curl -X POST http://localhost:8080/api/v1/gateway/routes/llm-service/shadow \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin-token" \
  -d '{
    "shadowUri": "http://mcp-llm-v2:5002",
    "percentage": 10
  }'
```

### Custom Response Headers

Add custom headers to responses:

```bash
curl -X POST http://localhost:8080/api/v1/gateway/routes/organization-service/headers \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin-token" \
  -d '{
    "responseHeaders": {
      "X-Custom-Header": "custom-value",
      "Cache-Control": "no-cache"
    }
  }'
```
