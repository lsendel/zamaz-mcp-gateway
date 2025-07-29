package com.zamaz.mcp.gateway.graphql.directive;

import com.zamaz.mcp.gateway.graphql.security.GraphQLSecurityService;
import graphql.schema.DataFetcher;
import graphql.schema.DataFetchingEnvironment;
import graphql.schema.GraphQLArgument;
import graphql.schema.GraphQLDirective;
import graphql.schema.GraphQLFieldDefinition;
import graphql.schema.idl.SchemaDirectiveWiring;
import graphql.schema.idl.SchemaDirectiveWiringEnvironment;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Auth directive implementation for GraphQL field authorization
 */
@RequiredArgsConstructor
@Slf4j
public class AuthDirective implements SchemaDirectiveWiring {

    private final GraphQLSecurityService securityService;

    @Override
    public GraphQLFieldDefinition onField(SchemaDirectiveWiringEnvironment<GraphQLFieldDefinition> environment) {
        GraphQLFieldDefinition field = environment.getElement();
        GraphQLDirective directive = environment.getDirective();
        
        // Extract directive arguments
        String requiredRole = getStringValue(directive, "requires", "USER");
        List<String> permissions = getListValue(directive, "permissions");
        
        // Get the original data fetcher
        DataFetcher<?> originalDataFetcher = field.getDataFetcher();
        
        // Create authorized data fetcher
        DataFetcher<?> authDataFetcher = (DataFetchingEnvironment env) -> {
            log.debug("Checking authorization for field: {} with role: {} and permissions: {}", 
                field.getName(), requiredRole, permissions);
            
            // Check authentication
            if (!securityService.isAuthenticated(env)) {
                log.warn("Unauthenticated access attempt to field: {}", field.getName());
                throw new GraphQLUnauthorizedException("Authentication required");
            }
            
            // Check authorization
            if (!securityService.hasRole(env, requiredRole)) {
                log.warn("Insufficient role for field: {}. Required: {}, User has: {}", 
                    field.getName(), requiredRole, securityService.getUserRole(env));
                throw new GraphQLUnauthorizedException("Insufficient permissions");
            }
            
            // Check specific permissions if provided
            if (permissions != null && !permissions.isEmpty()) {
                for (String permission : permissions) {
                    if (!securityService.hasPermission(env, permission)) {
                        log.warn("Missing permission: {} for field: {}", permission, field.getName());
                        throw new GraphQLUnauthorizedException("Missing permission: " + permission);
                    }
                }
            }
            
            log.debug("Authorization successful for field: {}", field.getName());
            
            // Call original data fetcher
            Object result = originalDataFetcher.get(env);
            
            // Handle CompletableFuture results
            if (result instanceof CompletableFuture) {
                return ((CompletableFuture<?>) result).exceptionally(throwable -> {
                    log.error("Error in authorized field: {}", field.getName(), throwable);
                    throw new RuntimeException(throwable);
                });
            }
            
            return result;
        };
        
        return field.transform(builder -> builder.dataFetcher(authDataFetcher));
    }

    private String getStringValue(GraphQLDirective directive, String argumentName, String defaultValue) {
        GraphQLArgument argument = directive.getArgument(argumentName);
        if (argument != null && argument.getArgumentDefaultValue() != null) {
            return argument.getArgumentDefaultValue().getValue().toString();
        }
        return defaultValue;
    }

    @SuppressWarnings("unchecked")
    private List<String> getListValue(GraphQLDirective directive, String argumentName) {
        GraphQLArgument argument = directive.getArgument(argumentName);
        if (argument != null && argument.getArgumentDefaultValue() != null) {
            Object value = argument.getArgumentDefaultValue().getValue();
            if (value instanceof List) {
                return (List<String>) value;
            }
        }
        return null;
    }

    public static class GraphQLUnauthorizedException extends RuntimeException {
        public GraphQLUnauthorizedException(String message) {
            super(message);
        }
    }
}