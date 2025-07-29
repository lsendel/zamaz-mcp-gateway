package com.zamaz.mcp.gateway.graphql.directive;

import graphql.schema.DataFetcher;
import graphql.schema.DataFetchingEnvironment;
import graphql.schema.GraphQLArgument;
import graphql.schema.GraphQLDirective;
import graphql.schema.GraphQLFieldDefinition;
import graphql.schema.idl.SchemaDirectiveWiring;
import graphql.schema.idl.SchemaDirectiveWiringEnvironment;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Pattern;

/**
 * Validation directive implementation for GraphQL fields
 */
@Slf4j
public class ValidateDirective implements SchemaDirectiveWiring {

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
        "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    );

    @Override
    public GraphQLFieldDefinition onField(SchemaDirectiveWiringEnvironment<GraphQLFieldDefinition> environment) {
        GraphQLFieldDefinition field = environment.getElement();
        GraphQLDirective directive = environment.getDirective();
        
        // Extract directive arguments
        String constraint = getStringValue(directive, "constraint", "");
        
        // Get the original data fetcher
        DataFetcher<?> originalDataFetcher = field.getDataFetcher();
        
        // Create validated data fetcher
        DataFetcher<?> validatedDataFetcher = (DataFetchingEnvironment env) -> {
            log.debug("Validating field: {} with constraint: {}", field.getName(), constraint);
            
            // Validate input arguments
            Map<String, Object> arguments = env.getArguments();
            validateArguments(arguments, constraint, field.getName());
            
            log.debug("Validation successful for field: {}", field.getName());
            
            // Call original data fetcher
            Object result = originalDataFetcher.get(env);
            
            // Handle CompletableFuture results
            if (result instanceof CompletableFuture) {
                return ((CompletableFuture<?>) result).exceptionally(throwable -> {
                    log.error("Error in validated field: {}", field.getName(), throwable);
                    throw new RuntimeException(throwable);
                });
            }
            
            return result;
        };
        
        return field.transform(builder -> builder.dataFetcher(validatedDataFetcher));
    }

    private void validateArguments(Map<String, Object> arguments, String constraint, String fieldName) {
        if (constraint.isEmpty()) {
            return;
        }

        for (Map.Entry<String, Object> entry : arguments.entrySet()) {
            String argName = entry.getKey();
            Object value = entry.getValue();
            
            if (value == null) {
                continue;
            }
            
            validateValue(value, constraint, fieldName, argName);
        }
    }

    private void validateValue(Object value, String constraint, String fieldName, String argName) {
        if (constraint.equals("email")) {
            validateEmail(value, fieldName, argName);
        } else if (constraint.startsWith("size(")) {
            validateSize(value, constraint, fieldName, argName);
        } else if (constraint.startsWith("min(")) {
            validateMin(value, constraint, fieldName, argName);
        } else if (constraint.startsWith("max(")) {
            validateMax(value, constraint, fieldName, argName);
        } else if (constraint.startsWith("pattern(")) {
            validatePattern(value, constraint, fieldName, argName);
        }
    }

    private void validateEmail(Object value, String fieldName, String argName) {
        if (value instanceof String) {
            String email = (String) value;
            if (!EMAIL_PATTERN.matcher(email).matches()) {
                throw new GraphQLValidationException(
                    String.format("Invalid email format in field %s.%s: %s", fieldName, argName, email)
                );
            }
        }
    }

    private void validateSize(Object value, String constraint, String fieldName, String argName) {
        if (value instanceof String) {
            String str = (String) value;
            int length = str.length();
            
            // Parse size constraint: size(min=1, max=100)
            int min = extractIntValue(constraint, "min", 0);
            int max = extractIntValue(constraint, "max", Integer.MAX_VALUE);
            
            if (length < min || length > max) {
                throw new GraphQLValidationException(
                    String.format("String length validation failed in field %s.%s: length=%d, min=%d, max=%d", 
                        fieldName, argName, length, min, max)
                );
            }
        }
    }

    private void validateMin(Object value, String constraint, String fieldName, String argName) {
        if (value instanceof Number) {
            Number num = (Number) value;
            int min = extractIntValue(constraint, "", 0);
            
            if (num.intValue() < min) {
                throw new GraphQLValidationException(
                    String.format("Minimum value validation failed in field %s.%s: value=%d, min=%d", 
                        fieldName, argName, num.intValue(), min)
                );
            }
        }
    }

    private void validateMax(Object value, String constraint, String fieldName, String argName) {
        if (value instanceof Number) {
            Number num = (Number) value;
            int max = extractIntValue(constraint, "", Integer.MAX_VALUE);
            
            if (num.intValue() > max) {
                throw new GraphQLValidationException(
                    String.format("Maximum value validation failed in field %s.%s: value=%d, max=%d", 
                        fieldName, argName, num.intValue(), max)
                );
            }
        }
    }

    private void validatePattern(Object value, String constraint, String fieldName, String argName) {
        if (value instanceof String) {
            String str = (String) value;
            String patternStr = extractStringValue(constraint, "", "");
            
            if (!patternStr.isEmpty()) {
                Pattern pattern = Pattern.compile(patternStr);
                if (!pattern.matcher(str).matches()) {
                    throw new GraphQLValidationException(
                        String.format("Pattern validation failed in field %s.%s: value=%s, pattern=%s", 
                            fieldName, argName, str, patternStr)
                    );
                }
            }
        }
    }

    private int extractIntValue(String constraint, String param, int defaultValue) {
        try {
            if (param.isEmpty()) {
                // Extract value from simple constraint like "min(5)"
                String valueStr = constraint.substring(constraint.indexOf('(') + 1, constraint.indexOf(')'));
                return Integer.parseInt(valueStr);
            } else {
                // Extract value from complex constraint like "size(min=1, max=100)"
                String paramPattern = param + "=";
                int start = constraint.indexOf(paramPattern);
                if (start != -1) {
                    start += paramPattern.length();
                    int end = constraint.indexOf(',', start);
                    if (end == -1) {
                        end = constraint.indexOf(')', start);
                    }
                    return Integer.parseInt(constraint.substring(start, end).trim());
                }
            }
        } catch (Exception e) {
            log.warn("Failed to extract int value from constraint: {}", constraint, e);
        }
        return defaultValue;
    }

    private String extractStringValue(String constraint, String param, String defaultValue) {
        try {
            if (param.isEmpty()) {
                // Extract value from simple constraint like "pattern(^[a-z]+$)"
                String valueStr = constraint.substring(constraint.indexOf('(') + 1, constraint.indexOf(')'));
                return valueStr.trim();
            }
        } catch (Exception e) {
            log.warn("Failed to extract string value from constraint: {}", constraint, e);
        }
        return defaultValue;
    }

    private String getStringValue(GraphQLDirective directive, String argumentName, String defaultValue) {
        GraphQLArgument argument = directive.getArgument(argumentName);
        if (argument != null && argument.getArgumentDefaultValue() != null) {
            return argument.getArgumentDefaultValue().getValue().toString();
        }
        return defaultValue;
    }

    public static class GraphQLValidationException extends RuntimeException {
        public GraphQLValidationException(String message) {
            super(message);
        }
    }
}