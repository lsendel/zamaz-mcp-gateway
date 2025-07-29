package com.zamaz.mcp.gateway.graphql.directive;

import graphql.schema.DataFetcher;
import graphql.schema.DataFetchingEnvironment;
import graphql.schema.GraphQLArgument;
import graphql.schema.GraphQLDirective;
import graphql.schema.GraphQLFieldDefinition;
import graphql.schema.idl.SchemaDirectiveWiring;
import graphql.schema.idl.SchemaDirectiveWiringEnvironment;
import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Rate limiting directive implementation for GraphQL fields
 */
@Slf4j
public class RateLimitDirective implements SchemaDirectiveWiring {

    private final ConcurrentHashMap<String, TokenBucket> buckets = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    @Override
    public GraphQLFieldDefinition onField(SchemaDirectiveWiringEnvironment<GraphQLFieldDefinition> environment) {
        GraphQLFieldDefinition field = environment.getElement();
        GraphQLDirective directive = environment.getDirective();
        
        // Extract directive arguments
        int maxRequests = getIntValue(directive, "max", 100);
        int windowSeconds = getIntValue(directive, "window", 60);
        
        // Get the original data fetcher
        DataFetcher<?> originalDataFetcher = field.getDataFetcher();
        
        // Create rate limited data fetcher
        DataFetcher<?> rateLimitedDataFetcher = (DataFetchingEnvironment env) -> {
            String clientId = getClientId(env);
            String key = field.getName() + ":" + clientId;
            
            log.debug("Checking rate limit for field: {} and client: {}", field.getName(), clientId);
            
            TokenBucket bucket = buckets.computeIfAbsent(key, k -> new TokenBucket(maxRequests, windowSeconds));
            
            if (!bucket.consume()) {
                log.warn("Rate limit exceeded for field: {} and client: {}", field.getName(), clientId);
                throw new GraphQLRateLimitExceededException(
                    String.format("Rate limit exceeded. Max %d requests per %d seconds", maxRequests, windowSeconds)
                );
            }
            
            log.debug("Rate limit check passed for field: {}, remaining: {}", field.getName(), bucket.getTokens());
            
            // Call original data fetcher
            Object result = originalDataFetcher.get(env);
            
            // Handle CompletableFuture results
            if (result instanceof CompletableFuture) {
                return ((CompletableFuture<?>) result).exceptionally(throwable -> {
                    log.error("Error in rate limited field: {}", field.getName(), throwable);
                    throw new RuntimeException(throwable);
                });
            }
            
            return result;
        };
        
        return field.transform(builder -> builder.dataFetcher(rateLimitedDataFetcher));
    }

    private int getIntValue(GraphQLDirective directive, String argumentName, int defaultValue) {
        GraphQLArgument argument = directive.getArgument(argumentName);
        if (argument != null && argument.getArgumentDefaultValue() != null) {
            return Integer.parseInt(argument.getArgumentDefaultValue().getValue().toString());
        }
        return defaultValue;
    }

    private String getClientId(DataFetchingEnvironment env) {
        // Try to get client ID from headers
        Object context = env.getContext();
        if (context instanceof graphql.kickstart.servlet.context.GraphQLServletContext) {
            graphql.kickstart.servlet.context.GraphQLServletContext servletContext = 
                (graphql.kickstart.servlet.context.GraphQLServletContext) context;
            
            // Try authorization header first
            String authHeader = servletContext.getHttpServletRequest().getHeader("Authorization");
            if (authHeader != null) {
                return authHeader.hashCode() + "";
            }
            
            // Fall back to IP address
            String clientIp = servletContext.getHttpServletRequest().getRemoteAddr();
            return clientIp != null ? clientIp : "unknown";
        }
        
        return "unknown";
    }

    /**
     * Token bucket implementation for rate limiting
     */
    private class TokenBucket {
        private final int maxTokens;
        private final int windowSeconds;
        private final AtomicInteger tokens;
        private volatile long lastRefillTime;

        public TokenBucket(int maxTokens, int windowSeconds) {
            this.maxTokens = maxTokens;
            this.windowSeconds = windowSeconds;
            this.tokens = new AtomicInteger(maxTokens);
            this.lastRefillTime = System.currentTimeMillis();
            
            // Schedule periodic refill
            scheduler.scheduleAtFixedRate(this::refill, windowSeconds, windowSeconds, TimeUnit.SECONDS);
        }

        public boolean consume() {
            refill();
            return tokens.getAndDecrement() > 0;
        }

        public int getTokens() {
            refill();
            return tokens.get();
        }

        private void refill() {
            long now = System.currentTimeMillis();
            long elapsed = now - lastRefillTime;
            
            if (elapsed >= windowSeconds * 1000) {
                tokens.set(maxTokens);
                lastRefillTime = now;
                log.debug("Refilled token bucket to {} tokens", maxTokens);
            }
        }
    }

    public static class GraphQLRateLimitExceededException extends RuntimeException {
        public GraphQLRateLimitExceededException(String message) {
            super(message);
        }
    }
}