package com.zamaz.mcp.gateway.filter;

import com.zamaz.mcp.security.service.JwtService;
import lombok.Data;
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
 * Gateway filter for JWT authentication
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AuthenticationGatewayFilterFactory extends AbstractGatewayFilterFactory<AuthenticationGatewayFilterFactory.Config> {

    private final JwtService jwtService;

    public AuthenticationGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            if (!config.isRequireAuth()) {
                return chain.filter(exchange);
            }

            String token = extractToken(exchange);
            
            if (token == null) {
                return onError(exchange, "Missing authentication token", HttpStatus.UNAUTHORIZED);
            }

            try {
                // Validate token
                if (!jwtService.validateToken(token)) {
                    return onError(exchange, "Invalid authentication token", HttpStatus.UNAUTHORIZED);
                }

                // Extract user information from token
                String userId = jwtService.extractUsername(token);
                List<String> roles = jwtService.extractRoles(token);

                // Check required role if specified
                if (config.getRequireRole() != null && !roles.contains(config.getRequireRole())) {
                    return onError(exchange, "Insufficient privileges", HttpStatus.FORBIDDEN);
                }

                // Add user information to headers for downstream services
                ServerWebExchange modifiedExchange = exchange.mutate()
                    .request(r -> r
                        .header("X-User-ID", userId)
                        .header("X-User-Roles", String.join(",", roles))
                        .header("X-Auth-Token", token)
                    )
                    .build();

                log.debug("Authentication successful for user: {}", userId);
                return chain.filter(modifiedExchange);

            } catch (Exception e) {
                log.error("Authentication error", e);
                return onError(exchange, "Authentication failed", HttpStatus.UNAUTHORIZED);
            }
        };
    }

    private String extractToken(ServerWebExchange exchange) {
        String bearerToken = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        exchange.getResponse().getHeaders().add("X-Auth-Error", err);
        return exchange.getResponse().setComplete();
    }

    @Data
    public static class Config {
        private boolean requireAuth = true;
        private String requireRole;
        private boolean checkOrgAccess = true;
    }
}