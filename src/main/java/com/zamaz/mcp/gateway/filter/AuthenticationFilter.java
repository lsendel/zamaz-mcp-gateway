package com.zamaz.mcp.gateway.filter;

import com.zamaz.mcp.security.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * JWT Authentication Filter for API Gateway
 * Validates JWT tokens and enriches requests with user context
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private final JwtTokenProvider jwtTokenProvider;
    
    // Paths that don't require authentication
    private static final List<String> OPEN_PATHS = List.of(
        "/api/v1/auth/login",
        "/api/v1/auth/register",
        "/api/v1/auth/refresh",
        "/health",
        "/actuator",
        "/swagger-ui",
        "/api-docs"
    );

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String path = exchange.getRequest().getURI().getPath();
            
            // Skip authentication for open paths
            if (isOpenPath(path)) {
                return chain.filter(exchange);
            }

            String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return handleUnauthorized(exchange);
            }

            String token = authHeader.substring(7);
            
            try {
                if (!jwtTokenProvider.validateToken(token)) {
                    return handleUnauthorized(exchange);
                }

                // Extract user information from token
                String userId = jwtTokenProvider.getUserIdFromToken(token);
                String organizationId = jwtTokenProvider.getOrganizationIdFromToken(token);
                List<String> roles = jwtTokenProvider.getRolesFromToken(token);

                // Enrich request with user context
                ServerWebExchange enrichedExchange = exchange.mutate()
                    .request(builder -> builder
                        .header("X-User-ID", userId)
                        .header("X-Organization-ID", organizationId)
                        .header("X-User-Roles", String.join(",", roles))
                        .header("X-Authenticated", "true"))
                    .build();

                log.debug("Authenticated user {} from organization {} with roles {}", 
                    userId, organizationId, roles);

                return chain.filter(enrichedExchange);

            } catch (Exception e) {
                log.warn("Authentication failed for token: {}", e.getMessage());
                return handleUnauthorized(exchange);
            }
        };
    }

    private boolean isOpenPath(String path) {
        return OPEN_PATHS.stream().anyMatch(path::startsWith);
    }

    private Mono<Void> handleUnauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        
        String body = "{\"error\":\"Unauthorized\",\"message\":\"Valid JWT token required\"}";
        var buffer = exchange.getResponse().bufferFactory().wrap(body.getBytes());
        
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    public static class Config {
        // Configuration properties if needed
    }
}