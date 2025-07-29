package com.zamaz.mcp.gateway.filter;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

/**
 * Gateway filter for response caching
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class ResponseCachingGatewayFilterFactory extends AbstractGatewayFilterFactory<ResponseCachingGatewayFilterFactory.Config> {

    private final ReactiveRedisTemplate<String, String> redisTemplate;

    public ResponseCachingGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerWebExchange.Builder exchangeBuilder = exchange.mutate();
            
            // Only cache GET requests
            if (exchange.getRequest().getMethod() != HttpMethod.GET) {
                return chain.filter(exchange);
            }
            
            String cacheKey = generateCacheKey(exchange, config);
            
            // Check cache first
            return redisTemplate.opsForValue().get(cacheKey)
                .flatMap(cachedResponse -> {
                    log.debug("Cache hit for key: {}", cacheKey);
                    
                    // Parse cached response
                    CachedResponse cached = parseCachedResponse(cachedResponse);
                    
                    // Set response headers
                    ServerHttpResponse response = exchange.getResponse();
                    response.setStatusCode(HttpStatus.valueOf(cached.statusCode));
                    response.getHeaders().addAll("X-Cache", List.of("HIT"));
                    response.getHeaders().addAll("X-Cache-Key", List.of(cacheKey));
                    cached.headers.forEach((key, values) -> response.getHeaders().addAll(key, values));
                    
                    // Write cached body
                    DataBuffer buffer = response.bufferFactory().wrap(cached.body.getBytes(StandardCharsets.UTF_8));
                    return response.writeWith(Mono.just(buffer));
                })
                .switchIfEmpty(
                    chain.filter(exchange.mutate()
                        .response(decorateResponse(exchange, config, cacheKey))
                        .build())
                );
        };
    }

    private ServerHttpResponseDecorator decorateResponse(ServerWebExchange exchange, Config config, String cacheKey) {
        ServerHttpResponse originalResponse = exchange.getResponse();
        DataBufferFactory bufferFactory = originalResponse.bufferFactory();
        
        return new ServerHttpResponseDecorator(originalResponse) {
            private final StringBuilder bodyBuilder = new StringBuilder();
            
            @Override
            public Mono<Void> writeWith(org.reactivestreams.Publisher<? extends DataBuffer> body) {
                if (body instanceof Flux) {
                    Flux<? extends DataBuffer> fluxBody = (Flux<? extends DataBuffer>) body;
                    
                    return super.writeWith(fluxBody.map(dataBuffer -> {
                        // Capture response body
                        byte[] content = new byte[dataBuffer.readableByteCount()];
                        dataBuffer.read(content);
                        bodyBuilder.append(new String(content, StandardCharsets.UTF_8));
                        
                        // Return new buffer
                        return bufferFactory.wrap(content);
                    })).doOnComplete(() -> {
                        // Cache the response if successful
                        if (shouldCache(originalResponse)) {
                            cacheResponse(cacheKey, originalResponse, bodyBuilder.toString(), config);
                        }
                    });
                }
                
                return super.writeWith(body);
            }
            
            @Override
            public Mono<Void> writeAndFlushWith(org.reactivestreams.Publisher<? extends org.reactivestreams.Publisher<? extends DataBuffer>> body) {
                return writeWith(Flux.from(body).flatMapSequential(p -> p));
            }
        };
    }

    private String generateCacheKey(ServerWebExchange exchange, Config config) {
        StringBuilder keyBuilder = new StringBuilder();
        keyBuilder.append(config.getCacheName()).append(":");
        keyBuilder.append(exchange.getRequest().getMethod()).append(":");
        keyBuilder.append(exchange.getRequest().getURI().getPath());
        
        // Include query parameters in cache key
        if (!exchange.getRequest().getQueryParams().isEmpty()) {
            keyBuilder.append("?");
            exchange.getRequest().getQueryParams().forEach((key, values) -> {
                keyBuilder.append(key).append("=").append(String.join(",", values)).append("&");
            });
        }
        
        // Include user ID for user-specific caching
        String userId = exchange.getRequest().getHeaders().getFirst("X-User-ID");
        if (userId != null && config.isUserSpecific()) {
            keyBuilder.append(":user:").append(userId);
        }
        
        // Include organization ID for org-specific caching
        String orgId = exchange.getRequest().getHeaders().getFirst("X-Organization-ID");
        if (orgId != null && config.isOrgSpecific()) {
            keyBuilder.append(":org:").append(orgId);
        }
        
        return keyBuilder.toString();
    }

    private boolean shouldCache(ServerHttpResponse response) {
        HttpStatus status = response.getStatusCode();
        if (status == null) {
            return false;
        }
        
        // Only cache successful responses
        return status.is2xxSuccessful();
    }

    private void cacheResponse(String cacheKey, ServerHttpResponse response, String body, Config config) {
        CachedResponse cachedResponse = new CachedResponse();
        cachedResponse.statusCode = response.getStatusCode().value();
        cachedResponse.headers = response.getHeaders();
        cachedResponse.body = body;
        
        String serialized = serializeCachedResponse(cachedResponse);
        
        redisTemplate.opsForValue()
            .set(cacheKey, serialized, config.getCacheDuration())
            .subscribe(
                success -> {
                    log.debug("Cached response for key: {} with TTL: {}", cacheKey, config.getCacheDuration());
                    response.getHeaders().add("X-Cache", "MISS");
                    response.getHeaders().add("X-Cache-Key", cacheKey);
                },
                error -> log.error("Failed to cache response", error)
            );
    }

    private String serializeCachedResponse(CachedResponse response) {
        // Simple serialization format
        StringBuilder sb = new StringBuilder();
        sb.append(response.statusCode).append("\n");
        response.headers.forEach((key, values) -> {
            sb.append(key).append(":").append(String.join(",", values)).append("\n");
        });
        sb.append("\n").append(response.body);
        return sb.toString();
    }

    private CachedResponse parseCachedResponse(String serialized) {
        CachedResponse response = new CachedResponse();
        String[] parts = serialized.split("\n\n", 2);
        String[] headerLines = parts[0].split("\n");
        
        response.statusCode = Integer.parseInt(headerLines[0]);
        response.headers = new org.springframework.http.HttpHeaders();
        
        for (int i = 1; i < headerLines.length; i++) {
            String[] headerParts = headerLines[i].split(":", 2);
            if (headerParts.length == 2) {
                response.headers.addAll(headerParts[0], List.of(headerParts[1].split(",")));
            }
        }
        
        response.body = parts.length > 1 ? parts[1] : "";
        return response;
    }

    @Data
    public static class Config {
        private String cacheName = "gateway-cache";
        private Duration cacheDuration = Duration.ofMinutes(5);
        private boolean userSpecific = false;
        private boolean orgSpecific = true;
        private List<String> excludeHeaders = List.of("Date", "X-Request-ID");
    }

    private static class CachedResponse {
        int statusCode;
        org.springframework.http.HttpHeaders headers;
        String body;
    }
}