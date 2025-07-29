package com.zamaz.mcp.gateway.config;

import com.zamaz.mcp.gateway.filter.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;

import java.time.Duration;
import java.time.LocalDateTime;

/**
 * Comprehensive API Gateway routing configuration with load balancing
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class RoutingConfig {

        private final RedisRateLimiter redisRateLimiter;
        private final KeyResolver userKeyResolver;
        private final AuthenticationGatewayFilterFactory authFilter;
        private final RequestLoggingGatewayFilterFactory loggingFilter;
        private final ResponseCachingGatewayFilterFactory cachingFilter;
        private final RequestValidationGatewayFilterFactory validationFilter;
        private final CircuitBreakerGatewayFilterFactory circuitBreakerFilter;

        @Value("${ORGANIZATION_SERVICE_URL}")
        private String organizationServiceUrl;

        @Value("${CONTROLLER_SERVICE_URL}")
        private String controllerServiceUrl;

        @Value("${LLM_SERVICE_URL}")
        private String llmServiceUrl;

        @Value("${RAG_SERVICE_URL}")
        private String ragServiceUrl;

        @Value("${TEMPLATE_SERVICE_URL}")
        private String templateServiceUrl;

        @Value("${CONTEXT_SERVICE_URL}")
        private String contextServiceUrl;

        @Value("${SECURITY_SERVICE_URL}")
        private String securityServiceUrl;

        @Value("${WEBSOCKET_URL}")
        private String websocketUrl;

        @Value("${LLM_CANARY_URL:http://localhost:5002-canary}")
        private String llmCanaryUrl;

        @Value("${WORKFLOW_SERVICE_URL}")
        private String workflowServiceUrl;

        @Value("${WORKFLOW_UI_URL}")
        private String workflowUiUrl;

        /**
         * Configure comprehensive routing for all microservices
         */
        @Bean
        public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
                return builder.routes()
                                // Health check routes (no authentication required)
                                .route("health_route", r -> r
                                                .path("/health", "/actuator/health/**")
                                                .filters(f -> f
                                                                .filter(loggingFilter.apply(
                                                                                config -> config.setLogLevel("INFO")))
                                                                .setResponseHeader("X-Health-Check",
                                                                                LocalDateTime.now().toString()))
                                                .uri("no://op"))

                                // Organization Service Routes
                                .route("organization_service", r -> r
                                                .path("/api/v*/organizations/**")
                                                .filters(f -> f
                                                                .filter(loggingFilter.apply(
                                                                                config -> config.setLogLevel("DEBUG")))
                                                                .filter(authFilter.apply(
                                                                                config -> config.setRequireAuth(true)))
                                                                .filter(validationFilter.apply(config -> config
                                                                                .setValidateOrgId(true)))
                                                                .requestRateLimiter(config -> config
                                                                                .setRateLimiter(redisRateLimiter)
                                                                                .setKeyResolver(userKeyResolver))
                                                                .circuitBreaker(config -> config
                                                                                .setName("organization-cb")
                                                                                .setFallbackUri("forward:/fallback/organization"))
                                                                .retry(config -> config
                                                                                .setRetries(3)
                                                                                .setStatuses(HttpStatus.BAD_GATEWAY,
                                                                                                HttpStatus.GATEWAY_TIMEOUT)
                                                                                .setMethods(HttpMethod.GET)))
                                                .uri(organizationServiceUrl))

                                // Debate Controller Service Routes
                                .route("debate_service", r -> r
                                                .path("/api/v*/debates/**")
                                                .filters(f -> f
                                                                .filter(loggingFilter.apply(
                                                                                config -> config.setLogLevel("DEBUG")))
                                                                .filter(authFilter.apply(
                                                                                config -> config.setRequireAuth(true)))
                                                                .filter(validationFilter.apply(config -> config
                                                                                .setValidateDebateAccess(true)))
                                                                .filter(cachingFilter.apply(config -> config
                                                                                .setCacheName("debates")
                                                                                .setCacheDuration(
                                                                                                Duration.ofMinutes(5))))
                                                                .requestRateLimiter(config -> config
                                                                                .setRateLimiter(redisRateLimiter)
                                                                                .setKeyResolver(userKeyResolver))
                                                                .circuitBreaker(config -> config
                                                                                .setName("debate-cb")
                                                                                .setFallbackUri("forward:/fallback/debate"))
                                                                .retry(config -> config
                                                                                .setRetries(2)
                                                                                .setStatuses(HttpStatus.SERVICE_UNAVAILABLE)))
                                                .uri(controllerServiceUrl))

                                // LLM Service Routes with Load Balancing
                                .route("llm_service", r -> r
                                                .path("/api/v*/llm/**", "/api/v*/providers/**")
                                                .filters(f -> f
                                                                .filter(loggingFilter.apply(
                                                                                config -> config.setLogLevel("INFO")))
                                                                .filter(authFilter.apply(
                                                                                config -> config.setRequireAuth(true)))
                                                                .filter(circuitBreakerFilter.apply(config -> config
                                                                                .setName("llm-cb")
                                                                                .setSlowCallDuration(
                                                                                                Duration.ofSeconds(30))
                                                                                .setSlowCallRateThreshold(50)))
                                                                .requestRateLimiter(config -> config
                                                                                .setRateLimiter(new RedisRateLimiter(10,
                                                                                                20, 1)) // Lower rate
                                                                                                        // for LLM
                                                                                .setKeyResolver(userKeyResolver))
                                                                .modifyRequestBody(String.class, String.class,
                                                                                (exchange, body) -> {
                                                                                        // Add request tracking
                                                                                        exchange.getAttributes().put(
                                                                                                        "request.start",
                                                                                                        System.currentTimeMillis());
                                                                                        return body;
                                                                                })
                                                                .modifyResponseBody(String.class, String.class,
                                                                                (exchange, body) -> {
                                                                                        // Add response time tracking
                                                                                        Long startTime = exchange
                                                                                                        .getAttribute("request.start");
                                                                                        if (startTime != null) {
                                                                                                long duration = System
                                                                                                                .currentTimeMillis()
                                                                                                                - startTime;
                                                                                                exchange.getResponse()
                                                                                                                .getHeaders()
                                                                                                                .add("X-Response-Time",
                                                                                                                                duration + "ms");
                                                                                        }
                                                                                        return body;
                                                                                }))
                                                .uri("lb://llm-service") // Load balanced URI
                                )

                                // RAG Service Routes
                                .route("rag_service", r -> r
                                                .path("/api/v*/rag/**", "/api/v*/search/**")
                                                .filters(f -> f
                                                                .filter(loggingFilter.apply(
                                                                                config -> config.setLogLevel("INFO")))
                                                                .filter(authFilter.apply(
                                                                                config -> config.setRequireAuth(true)))
                                                                .filter(cachingFilter.apply(config -> config
                                                                                .setCacheName("rag-search")
                                                                                .setCacheDuration(Duration
                                                                                                .ofMinutes(15))))
                                                                .requestRateLimiter(config -> config
                                                                                .setRateLimiter(redisRateLimiter)
                                                                                .setKeyResolver(userKeyResolver))
                                                                .circuitBreaker(config -> config
                                                                                .setName("rag-cb")
                                                                                .setFallbackUri("forward:/fallback/rag")))
                                                .uri(ragServiceUrl))

                                // Template Service Routes
                                .route("template_service", r -> r
                                                .path("/api/v*/templates/**")
                                                .filters(f -> f
                                                                .filter(loggingFilter.apply(
                                                                                config -> config.setLogLevel("DEBUG")))
                                                                .filter(authFilter.apply(
                                                                                config -> config.setRequireAuth(true)))
                                                                .filter(validationFilter.apply(config -> config
                                                                                .setValidateTemplateAccess(true)))
                                                                .filter(cachingFilter.apply(config -> config
                                                                                .setCacheName("templates")
                                                                                .setCacheDuration(Duration.ofHours(1))))
                                                                .requestRateLimiter(config -> config
                                                                                .setRateLimiter(redisRateLimiter)
                                                                                .setKeyResolver(userKeyResolver)))
                                                .uri(templateServiceUrl))

                                // Context Service Routes
                                .route("context_service", r -> r
                                                .path("/api/v*/contexts/**")
                                                .filters(f -> f
                                                                .filter(loggingFilter.apply(
                                                                                config -> config.setLogLevel("DEBUG")))
                                                                .filter(authFilter.apply(
                                                                                config -> config.setRequireAuth(true)))
                                                                .filter(validationFilter.apply(config -> config
                                                                                .setValidateContextAccess(true)))
                                                                .requestRateLimiter(config -> config
                                                                                .setRateLimiter(redisRateLimiter)
                                                                                .setKeyResolver(userKeyResolver))
                                                                .circuitBreaker(config -> config
                                                                                .setName("context-cb")
                                                                                .setFallbackUri("forward:/fallback/context")))
                                                .uri(contextServiceUrl))

                                // Workflow Service Routes
                                .route("workflow_service", r -> r
                                                .path("/api/v*/workflows/**", "/graphql/workflow/**")
                                                .filters(f -> f
                                                                .filter(loggingFilter.apply(
                                                                                config -> config.setLogLevel("DEBUG")))
                                                                .filter(authFilter.apply(
                                                                                config -> config.setRequireAuth(true)))
                                                                .filter(validationFilter.apply(config -> config
                                                                                .setValidateOrgId(true)))
                                                                .requestRateLimiter(config -> config
                                                                                .setRateLimiter(redisRateLimiter)
                                                                                .setKeyResolver(userKeyResolver))
                                                                .circuitBreaker(config -> config
                                                                                .setName("workflow-cb")
                                                                                .setFallbackUri("forward:/fallback/workflow"))
                                                                .retry(config -> config
                                                                                .setRetries(2)
                                                                                .setStatuses(HttpStatus.SERVICE_UNAVAILABLE)))
                                                .uri(workflowServiceUrl))

                                // Workflow UI Routes (for iframe integration)
                                .route("workflow_ui", r -> r
                                                .path("/workflow-ui/**")
                                                .filters(f -> f
                                                                .filter(loggingFilter.apply(
                                                                                config -> config.setLogLevel("INFO")))
                                                                .filter(authFilter.apply(
                                                                                config -> config.setRequireAuth(true)))
                                                                .rewritePath("/workflow-ui/(?<segment>.*)",
                                                                                "/${segment}"))
                                                .uri(workflowUiUrl))

                                // Security Service Routes (Auth endpoints)
                                .route("auth_routes", r -> r
                                                .path("/api/v*/auth/**", "/api/v*/users/**")
                                                .filters(f -> f
                                                                .filter(loggingFilter.apply(config -> config
                                                                                .setLogLevel("INFO")
                                                                                .setLogSensitive(false) // Don't log
                                                                                                        // passwords
                                                                ))
                                                                .requestRateLimiter(config -> config
                                                                                .setRateLimiter(new RedisRateLimiter(5,
                                                                                                10, 1)) // Strict rate
                                                                                                        // limit for
                                                                                                        // auth
                                                                                .setKeyResolver(exchange -> exchange
                                                                                                .getRequest()
                                                                                                .getRemoteAddress()
                                                                                                .map(addr -> addr
                                                                                                                .getAddress()
                                                                                                                .getHostAddress())
                                                                                                .map(ip -> "auth:" + ip)
                                                                                                .defaultIfEmpty("auth:unknown"))))
                                                .uri(securityServiceUrl))

                                // OAuth2/SSO Routes
                                .route("oauth2_routes", r -> r
                                                .path("/oauth2/**", "/login/oauth2/**")
                                                .filters(f -> f
                                                                .filter(loggingFilter.apply(
                                                                                config -> config.setLogLevel("INFO"))))
                                                .uri(securityServiceUrl))

                                // WebSocket Routes for real-time updates
                                .route("websocket_route", r -> r
                                                .path("/ws/**")
                                                .filters(f -> f
                                                                .filter(authFilter.apply(
                                                                                config -> config.setRequireAuth(true))))
                                                .uri(websocketUrl))

                                // API Documentation Routes
                                .route("api_docs", r -> r
                                                .path("/api-docs/**", "/swagger-ui/**", "/v3/api-docs/**")
                                                .filters(f -> f
                                                                .filter(loggingFilter.apply(
                                                                                config -> config.setLogLevel("INFO")))
                                                                .filter(cachingFilter.apply(config -> config
                                                                                .setCacheName("api-docs")
                                                                                .setCacheDuration(
                                                                                                Duration.ofHours(24)))))
                                                .uri("no://op"))

                                // Metrics and Monitoring Routes
                                .route("metrics_route", r -> r
                                                .path("/metrics", "/actuator/**")
                                                .filters(f -> f
                                                                .filter(authFilter.apply(config -> config
                                                                                .setRequireAuth(true)
                                                                                .setRequireRole("ADMIN"))))
                                                .uri("no://op"))

                                // Default fallback route
                                .route("fallback_route", r -> r
                                                .path("/fallback/**")
                                                .filters(f -> f
                                                                .setStatus(HttpStatus.SERVICE_UNAVAILABLE)
                                                                .setResponseHeader("X-Fallback", "true"))
                                                .uri("no://op"))

                                .build();
        }

        /**
         * Configure routes for API versioning
         */
        @Bean
        public RouteLocator versionedRoutes(RouteLocatorBuilder builder) {
                return builder.routes()
                                // Version 1 routes
                                .route("v1_routes", r -> r
                                                .path("/api/v1/**")
                                                .filters(f -> f
                                                                .setRequestHeader("X-API-Version", "1.0")
                                                                .filter(loggingFilter.apply(
                                                                                config -> config.setLogLevel("INFO"))))
                                                .uri("no://op"))

                                // Version 2 routes (with breaking changes)
                                .route("v2_routes", r -> r
                                                .path("/api/v2/**")
                                                .filters(f -> f
                                                                .setRequestHeader("X-API-Version", "2.0")
                                                                .filter(loggingFilter.apply(
                                                                                config -> config.setLogLevel("INFO")))
                                                                .filter(validationFilter.apply(config -> config
                                                                                .setStrictValidation(true))))
                                                .uri("no://op"))

                                .build();
        }

        /**
         * Configure load balancing for high-traffic services
         */
        @Bean
        public RouteLocator loadBalancedRoutes(RouteLocatorBuilder builder) {
                return builder.routes()
                                // Load balanced LLM service with multiple instances
                                .route("llm_lb_route", r -> r
                                                .path("/api/v*/llm/generate/**")
                                                .filters(f -> f
                                                                .filter(loggingFilter.apply(
                                                                                config -> config.setLogLevel("INFO")))
                                                                .filter(authFilter.apply(
                                                                                config -> config.setRequireAuth(true)))
                                                                .requestRateLimiter(config -> config
                                                                                .setRateLimiter(new RedisRateLimiter(5,
                                                                                                10, 1))
                                                                                .setKeyResolver(userKeyResolver))
                                                                .retry(config -> config
                                                                                .setRetries(2)
                                                                                .setBackoff(Duration.ofSeconds(1),
                                                                                                Duration.ofSeconds(5),
                                                                                                2, true)))
                                                .uri("lb://llm-service")
                                                .metadata("lb-algorithm", "round-robin")
                                                .metadata("health-check-interval", "10s")
                                                .metadata("health-check-timeout", "3s"))

                                // Load balanced debate service for high availability
                                .route("debate_lb_route", r -> r
                                                .path("/api/v*/debates/active/**")
                                                .filters(f -> f
                                                                .filter(loggingFilter.apply(
                                                                                config -> config.setLogLevel("DEBUG")))
                                                                .filter(authFilter.apply(
                                                                                config -> config.setRequireAuth(true)))
                                                                .circuitBreaker(config -> config
                                                                                .setName("debate-lb-cb")
                                                                                .setFallbackUri("forward:/fallback/debate")))
                                                .uri("lb://debate-service")
                                                .metadata("lb-algorithm", "least-connections")
                                                .metadata("sticky-sessions", "true"))

                                .build();
        }

        /**
         * Configure canary deployment routes
         */
        @Bean
        public RouteLocator canaryRoutes(RouteLocatorBuilder builder) {
                return builder.routes()
                                // Canary deployment for new LLM model
                                .route("llm_canary", r -> r
                                                .path("/api/v*/llm/generate/**")
                                                .and()
                                                .header("X-Canary", "true")
                                                .filters(f -> f
                                                                .filter(loggingFilter.apply(config -> config
                                                                                .setLogLevel("DEBUG")
                                                                                .setLogTag("CANARY")))
                                                                .setRequestHeader("X-Route-To", "canary"))
                                                .uri(llmCanaryUrl))

                                // A/B testing route
                                .route("ab_test_route", r -> r
                                                .path("/api/v*/debates/create")
                                                .and()
                                                .weight("ab-test", 10) // 10% traffic to new version
                                                .filters(f -> f
                                                                .filter(loggingFilter.apply(
                                                                                config -> config.setLogTag("AB-TEST")))
                                                                .setRequestHeader("X-AB-Test", "variant-b"))
                                                .uri(controllerServiceUrl + "-v2"))

                                .build();
        }
}