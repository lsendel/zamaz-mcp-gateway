package com.zamaz.mcp.gateway.filter;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * Gateway filter for comprehensive request/response logging
 */
@Component
@Slf4j
public class RequestLoggingGatewayFilterFactory extends AbstractGatewayFilterFactory<RequestLoggingGatewayFilterFactory.Config> {

    public RequestLoggingGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String requestId = UUID.randomUUID().toString();
            MDC.put("requestId", requestId);
            
            ServerHttpRequest request = exchange.getRequest();
            
            // Log request details
            logRequest(request, config, requestId);
            
            // Add request ID to headers
            ServerHttpRequest modifiedRequest = request.mutate()
                .header("X-Request-ID", requestId)
                .build();
            
            long startTime = System.currentTimeMillis();
            
            // Log request body if needed
            if (config.isLogBody() && shouldLogBody(request.getMethod())) {
                return DataBufferUtils.join(request.getBody())
                    .flatMap(dataBuffer -> {
                        byte[] bytes = new byte[dataBuffer.readableByteCount()];
                        dataBuffer.read(bytes);
                        DataBufferUtils.release(dataBuffer);
                        
                        String body = new String(bytes, StandardCharsets.UTF_8);
                        if (!config.isLogSensitive()) {
                            body = maskSensitiveData(body);
                        }
                        
                        log.debug("[{}] Request body: {}", requestId, body);
                        
                        // Create new request with cached body
                        ServerHttpRequest cachedRequest = new ServerHttpRequestDecorator(modifiedRequest) {
                            @Override
                            public Flux<DataBuffer> getBody() {
                                return Flux.just(exchange.getResponse().bufferFactory().wrap(bytes));
                            }
                        };
                        
                        return chain.filter(exchange.mutate().request(cachedRequest).build());
                    })
                    .doFinally(signalType -> {
                        logResponse(exchange, config, requestId, startTime);
                        MDC.remove("requestId");
                    });
            }
            
            return chain.filter(exchange.mutate().request(modifiedRequest).build())
                .doFinally(signalType -> {
                    logResponse(exchange, config, requestId, startTime);
                    MDC.remove("requestId");
                });
        };
    }

    private void logRequest(ServerHttpRequest request, Config config, String requestId) {
        String logLevel = config.getLogLevel();
        String logTag = config.getLogTag() != null ? "[" + config.getLogTag() + "] " : "";
        
        String message = String.format("%s[%s] --> %s %s from %s",
            logTag,
            requestId,
            request.getMethod(),
            request.getURI().getPath(),
            request.getRemoteAddress() != null ? request.getRemoteAddress().getAddress().getHostAddress() : "unknown"
        );
        
        logAtLevel(logLevel, message);
        
        // Log headers if debug level
        if ("DEBUG".equalsIgnoreCase(logLevel)) {
            request.getHeaders().forEach((name, values) -> {
                if (!isSensitiveHeader(name)) {
                    log.debug("[{}] Header: {} = {}", requestId, name, values);
                }
            });
        }
    }

    private void logResponse(org.springframework.web.server.ServerWebExchange exchange, Config config, String requestId, long startTime) {
        long duration = System.currentTimeMillis() - startTime;
        String logLevel = config.getLogLevel();
        String logTag = config.getLogTag() != null ? "[" + config.getLogTag() + "] " : "";
        
        String message = String.format("%s[%s] <-- %s %s (%d) in %dms",
            logTag,
            requestId,
            exchange.getRequest().getMethod(),
            exchange.getRequest().getURI().getPath(),
            exchange.getResponse().getStatusCode() != null ? exchange.getResponse().getStatusCode().value() : 0,
            duration
        );
        
        logAtLevel(logLevel, message);
        
        // Add response time header
        exchange.getResponse().getHeaders().add("X-Response-Time", duration + "ms");
        exchange.getResponse().getHeaders().add("X-Request-ID", requestId);
    }

    private boolean shouldLogBody(HttpMethod method) {
        return method == HttpMethod.POST || method == HttpMethod.PUT || method == HttpMethod.PATCH;
    }

    private boolean isSensitiveHeader(String headerName) {
        String lower = headerName.toLowerCase();
        return lower.contains("authorization") || 
               lower.contains("cookie") || 
               lower.contains("x-api-key") ||
               lower.contains("x-auth-token");
    }

    private String maskSensitiveData(String data) {
        // Mask passwords
        data = data.replaceAll("\"password\"\\s*:\\s*\"[^\"]+\"", "\"password\":\"***\"");
        data = data.replaceAll("\"oldPassword\"\\s*:\\s*\"[^\"]+\"", "\"oldPassword\":\"***\"");
        data = data.replaceAll("\"newPassword\"\\s*:\\s*\"[^\"]+\"", "\"newPassword\":\"***\"");
        data = data.replaceAll("\"confirmPassword\"\\s*:\\s*\"[^\"]+\"", "\"confirmPassword\":\"***\"");
        
        // Mask tokens
        data = data.replaceAll("\"token\"\\s*:\\s*\"[^\"]+\"", "\"token\":\"***\"");
        data = data.replaceAll("\"refreshToken\"\\s*:\\s*\"[^\"]+\"", "\"refreshToken\":\"***\"");
        
        // Mask API keys
        data = data.replaceAll("\"apiKey\"\\s*:\\s*\"[^\"]+\"", "\"apiKey\":\"***\"");
        data = data.replaceAll("\"secretKey\"\\s*:\\s*\"[^\"]+\"", "\"secretKey\":\"***\"");
        
        return data;
    }

    private void logAtLevel(String level, String message) {
        switch (level.toUpperCase()) {
            case "TRACE":
                log.trace(message);
                break;
            case "DEBUG":
                log.debug(message);
                break;
            case "INFO":
                log.info(message);
                break;
            case "WARN":
                log.warn(message);
                break;
            case "ERROR":
                log.error(message);
                break;
            default:
                log.info(message);
        }
    }

    @Data
    public static class Config {
        private String logLevel = "INFO";
        private boolean logBody = false;
        private boolean logSensitive = false;
        private String logTag;
    }
}