package com.zamaz.mcp.gateway.filter;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.regex.Pattern;

/**
 * Gateway filter for request validation
 */
@Component
@Slf4j
public class RequestValidationGatewayFilterFactory extends AbstractGatewayFilterFactory<RequestValidationGatewayFilterFactory.Config> {

    private static final Pattern UUID_PATTERN = Pattern.compile(
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    );

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
        "^[A-Za-z0-9+_.-]+@([A-Za-z0-9.-]+\\.[A-Za-z]{2,})$"
    );

    public RequestValidationGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            // Validate organization ID
            if (config.isValidateOrgId()) {
                String orgId = exchange.getRequest().getHeaders().getFirst("X-Organization-ID");
                if (orgId == null || orgId.trim().isEmpty()) {
                    return onError(exchange, "Missing organization ID", HttpStatus.BAD_REQUEST);
                }
                if (!isValidId(orgId)) {
                    return onError(exchange, "Invalid organization ID format", HttpStatus.BAD_REQUEST);
                }
            }

            // Validate debate access
            if (config.isValidateDebateAccess()) {
                String path = exchange.getRequest().getURI().getPath();
                String debateId = extractDebateId(path);
                if (debateId != null && !isValidId(debateId)) {
                    return onError(exchange, "Invalid debate ID format", HttpStatus.BAD_REQUEST);
                }
            }

            // Validate template access
            if (config.isValidateTemplateAccess()) {
                String path = exchange.getRequest().getURI().getPath();
                String templateId = extractTemplateId(path);
                if (templateId != null && !isValidId(templateId)) {
                    return onError(exchange, "Invalid template ID format", HttpStatus.BAD_REQUEST);
                }
            }

            // Validate context access
            if (config.isValidateContextAccess()) {
                String path = exchange.getRequest().getURI().getPath();
                String contextId = extractContextId(path);
                if (contextId != null && !isValidId(contextId)) {
                    return onError(exchange, "Invalid context ID format", HttpStatus.BAD_REQUEST);
                }
            }

            // Validate request size
            String contentLength = exchange.getRequest().getHeaders().getFirst("Content-Length");
            if (contentLength != null) {
                try {
                    long length = Long.parseLong(contentLength);
                    if (length > config.getMaxRequestSize()) {
                        return onError(exchange, "Request size exceeds limit", HttpStatus.PAYLOAD_TOO_LARGE);
                    }
                } catch (NumberFormatException e) {
                    return onError(exchange, "Invalid content length", HttpStatus.BAD_REQUEST);
                }
            }

            // Validate content type for POST/PUT requests
            if (isBodyRequest(exchange) && config.isValidateContentType()) {
                String contentType = exchange.getRequest().getHeaders().getFirst("Content-Type");
                if (contentType == null || !contentType.contains("application/json")) {
                    return onError(exchange, "Content-Type must be application/json", HttpStatus.UNSUPPORTED_MEDIA_TYPE);
                }
            }

            // Strict validation mode
            if (config.isStrictValidation()) {
                // Validate all headers
                if (!validateHeaders(exchange)) {
                    return onError(exchange, "Invalid request headers", HttpStatus.BAD_REQUEST);
                }

                // Validate query parameters
                if (!validateQueryParams(exchange)) {
                    return onError(exchange, "Invalid query parameters", HttpStatus.BAD_REQUEST);
                }
            }

            return chain.filter(exchange);
        };
    }

    private boolean isValidId(String id) {
        // Accept both UUID format and custom ID format (e.g., "org-123", "debate-456")
        return UUID_PATTERN.matcher(id).matches() || 
               id.matches("^[a-zA-Z]+-[a-zA-Z0-9]+$");
    }

    private String extractDebateId(String path) {
        if (path.contains("/debates/")) {
            String[] parts = path.split("/debates/");
            if (parts.length > 1) {
                String[] idParts = parts[1].split("/");
                return idParts[0];
            }
        }
        return null;
    }

    private String extractTemplateId(String path) {
        if (path.contains("/templates/")) {
            String[] parts = path.split("/templates/");
            if (parts.length > 1) {
                String[] idParts = parts[1].split("/");
                return idParts[0];
            }
        }
        return null;
    }

    private String extractContextId(String path) {
        if (path.contains("/contexts/")) {
            String[] parts = path.split("/contexts/");
            if (parts.length > 1) {
                String[] idParts = parts[1].split("/");
                return idParts[0];
            }
        }
        return null;
    }

    private boolean isBodyRequest(ServerWebExchange exchange) {
        String method = exchange.getRequest().getMethod().toString();
        return "POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method);
    }

    private boolean validateHeaders(ServerWebExchange exchange) {
        // Validate required headers
        String requestId = exchange.getRequest().getHeaders().getFirst("X-Request-ID");
        if (requestId != null && !isValidRequestId(requestId)) {
            return false;
        }

        // Check for SQL injection patterns in headers
        return exchange.getRequest().getHeaders().toSingleValueMap().values().stream()
            .noneMatch(this::containsSqlInjectionPattern);
    }

    private boolean validateQueryParams(ServerWebExchange exchange) {
        // Check for SQL injection patterns in query parameters
        return exchange.getRequest().getQueryParams().toSingleValueMap().values().stream()
            .noneMatch(this::containsSqlInjectionPattern);
    }

    private boolean isValidRequestId(String requestId) {
        return requestId.matches("^[a-zA-Z0-9-]{1,64}$");
    }

    private boolean containsSqlInjectionPattern(String value) {
        if (value == null) {
            return false;
        }
        
        String lower = value.toLowerCase();
        return lower.contains("union select") ||
               lower.contains("drop table") ||
               lower.contains("insert into") ||
               lower.contains("delete from") ||
               lower.contains("update set") ||
               lower.matches(".*\\b(or|and)\\s+\\d+\\s*=\\s*\\d+.*") ||
               lower.contains("--") ||
               lower.contains("/*") ||
               lower.contains("*/") ||
               lower.contains("xp_") ||
               lower.contains("sp_");
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        log.warn("Request validation failed: {} for path: {}", err, exchange.getRequest().getURI().getPath());
        exchange.getResponse().setStatusCode(httpStatus);
        exchange.getResponse().getHeaders().add("X-Validation-Error", err);
        return exchange.getResponse().setComplete();
    }

    @Data
    public static class Config {
        private boolean validateOrgId = true;
        private boolean validateDebateAccess = false;
        private boolean validateTemplateAccess = false;
        private boolean validateContextAccess = false;
        private boolean validateContentType = true;
        private boolean strictValidation = false;
        private long maxRequestSize = 1024 * 1024 * 10; // 10MB default
    }
}