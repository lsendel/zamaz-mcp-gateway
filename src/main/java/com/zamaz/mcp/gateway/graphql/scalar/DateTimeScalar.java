package com.zamaz.mcp.gateway.graphql.scalar;

import graphql.language.StringValue;
import graphql.schema.Coercing;
import graphql.schema.CoercingParseLiteralException;
import graphql.schema.CoercingParseValueException;
import graphql.schema.CoercingSerializeException;
import graphql.schema.GraphQLScalarType;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

/**
 * Custom GraphQL scalar for DateTime handling
 */
public class DateTimeScalar {

    private static final DateTimeFormatter ISO_DATE_TIME_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    public static final GraphQLScalarType INSTANCE = GraphQLScalarType.newScalar()
        .name("DateTime")
        .description("DateTime scalar type")
        .coercing(new Coercing<LocalDateTime, String>() {
            
            @Override
            public String serialize(Object dataFetcherResult) throws CoercingSerializeException {
                if (dataFetcherResult instanceof LocalDateTime) {
                    return ((LocalDateTime) dataFetcherResult).format(ISO_DATE_TIME_FORMATTER);
                } else if (dataFetcherResult instanceof String) {
                    return (String) dataFetcherResult;
                } else {
                    throw new CoercingSerializeException("Expected LocalDateTime or String, got " + dataFetcherResult.getClass().getSimpleName());
                }
            }

            @Override
            public LocalDateTime parseValue(Object input) throws CoercingParseValueException {
                if (input instanceof String) {
                    try {
                        return LocalDateTime.parse((String) input, ISO_DATE_TIME_FORMATTER);
                    } catch (DateTimeParseException e) {
                        throw new CoercingParseValueException("Invalid DateTime format: " + input, e);
                    }
                } else if (input instanceof LocalDateTime) {
                    return (LocalDateTime) input;
                } else {
                    throw new CoercingParseValueException("Expected String or LocalDateTime, got " + input.getClass().getSimpleName());
                }
            }

            @Override
            public LocalDateTime parseLiteral(Object input) throws CoercingParseLiteralException {
                if (input instanceof StringValue) {
                    try {
                        return LocalDateTime.parse(((StringValue) input).getValue(), ISO_DATE_TIME_FORMATTER);
                    } catch (DateTimeParseException e) {
                        throw new CoercingParseLiteralException("Invalid DateTime format: " + ((StringValue) input).getValue(), e);
                    }
                } else {
                    throw new CoercingParseLiteralException("Expected StringValue, got " + input.getClass().getSimpleName());
                }
            }
        })
        .build();
}