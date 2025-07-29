package com.zamaz.mcp.gateway.graphql.scalar;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import graphql.language.StringValue;
import graphql.schema.Coercing;
import graphql.schema.CoercingParseLiteralException;
import graphql.schema.CoercingParseValueException;
import graphql.schema.CoercingSerializeException;
import graphql.schema.GraphQLScalarType;

import java.util.Map;

/**
 * Custom GraphQL scalar for JSON handling
 */
public class JsonScalar {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static final GraphQLScalarType INSTANCE = GraphQLScalarType.newScalar()
        .name("JSON")
        .description("JSON scalar type")
        .coercing(new Coercing<Object, Object>() {
            
            @Override
            public Object serialize(Object dataFetcherResult) throws CoercingSerializeException {
                if (dataFetcherResult == null) {
                    return null;
                }
                
                if (dataFetcherResult instanceof String) {
                    try {
                        // Validate that it's valid JSON
                        OBJECT_MAPPER.readTree((String) dataFetcherResult);
                        return dataFetcherResult;
                    } catch (JsonProcessingException e) {
                        throw new CoercingSerializeException("Invalid JSON string: " + dataFetcherResult, e);
                    }
                } else if (dataFetcherResult instanceof JsonNode) {
                    return dataFetcherResult.toString();
                } else if (dataFetcherResult instanceof Map || dataFetcherResult instanceof java.util.List) {
                    try {
                        return OBJECT_MAPPER.writeValueAsString(dataFetcherResult);
                    } catch (JsonProcessingException e) {
                        throw new CoercingSerializeException("Could not serialize object to JSON", e);
                    }
                } else {
                    return dataFetcherResult.toString();
                }
            }

            @Override
            public Object parseValue(Object input) throws CoercingParseValueException {
                if (input == null) {
                    return null;
                }
                
                if (input instanceof String) {
                    try {
                        return OBJECT_MAPPER.readTree((String) input);
                    } catch (JsonProcessingException e) {
                        throw new CoercingParseValueException("Invalid JSON string: " + input, e);
                    }
                } else if (input instanceof Map || input instanceof java.util.List) {
                    return input;
                } else {
                    throw new CoercingParseValueException("Expected String, Map, or List, got " + input.getClass().getSimpleName());
                }
            }

            @Override
            public Object parseLiteral(Object input) throws CoercingParseLiteralException {
                if (input instanceof StringValue) {
                    try {
                        return OBJECT_MAPPER.readTree(((StringValue) input).getValue());
                    } catch (JsonProcessingException e) {
                        throw new CoercingParseLiteralException("Invalid JSON string: " + ((StringValue) input).getValue(), e);
                    }
                } else {
                    throw new CoercingParseLiteralException("Expected StringValue, got " + input.getClass().getSimpleName());
                }
            }
        })
        .build();
}