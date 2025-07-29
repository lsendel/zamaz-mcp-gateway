package com.zamaz.mcp.gateway.graphql;

import graphql.ErrorClassification;
import graphql.ErrorType;
import graphql.GraphQLError;
import graphql.language.SourceLocation;
import lombok.RequiredArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * GraphQL error adapter for consistent error handling
 */
@RequiredArgsConstructor
public class GraphQLErrorAdapter implements GraphQLError {

    private final Throwable exception;

    @Override
    public String getMessage() {
        return exception.getMessage();
    }

    @Override
    public List<SourceLocation> getLocations() {
        return null;
    }

    @Override
    public ErrorClassification getErrorType() {
        if (exception instanceof IllegalArgumentException) {
            return ErrorType.ValidationError;
        } else if (exception instanceof SecurityException) {
            return ErrorType.ExecutionAborted;
        } else if (exception instanceof RuntimeException) {
            return ErrorType.DataFetchingException;
        } else {
            return ErrorType.ExecutionAborted;
        }
    }

    @Override
    public Map<String, Object> getExtensions() {
        return Map.of(
            "exception", exception.getClass().getSimpleName(),
            "timestamp", System.currentTimeMillis()
        );
    }
}