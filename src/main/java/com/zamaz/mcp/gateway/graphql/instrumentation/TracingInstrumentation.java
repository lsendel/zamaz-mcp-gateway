package com.zamaz.mcp.gateway.graphql.instrumentation;

import graphql.ExecutionResult;
import graphql.execution.instrumentation.ExecutionStrategyInstrumentationContext;
import graphql.execution.instrumentation.InstrumentationContext;
import graphql.execution.instrumentation.InstrumentationState;
import graphql.execution.instrumentation.SimpleInstrumentation;
import graphql.execution.instrumentation.parameters.InstrumentationExecutionParameters;
import graphql.execution.instrumentation.parameters.InstrumentationExecutionStrategyParameters;
import graphql.execution.instrumentation.parameters.InstrumentationFieldFetchParameters;
import graphql.execution.instrumentation.parameters.InstrumentationValidationParameters;
import graphql.language.Document;
import graphql.schema.DataFetcher;
import graphql.validation.ValidationError;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.Scope;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * GraphQL instrumentation for distributed tracing
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class TracingInstrumentation extends SimpleInstrumentation {

    private final Tracer tracer;

    @Override
    public InstrumentationState createState() {
        return new TracingInstrumentationState();
    }

    @Override
    public InstrumentationContext<ExecutionResult> beginExecution(
            InstrumentationExecutionParameters parameters) {
        
        TracingInstrumentationState state = parameters.getInstrumentationState();
        
        String operationName = parameters.getOperation() != null ? 
            parameters.getOperation() : "GraphQL Operation";
        
        Span span = tracer.spanBuilder("graphql.execution")
            .setAttribute("graphql.operation.name", operationName)
            .setAttribute("graphql.operation.type", getOperationType(parameters.getDocument()))
            .startSpan();
        
        state.setExecutionSpan(span);
        state.setExecutionScope(span.makeCurrent());
        
        log.debug("Started GraphQL execution tracing for operation: {}", operationName);
        
        return new InstrumentationContext<ExecutionResult>() {
            @Override
            public void onCompleted(ExecutionResult result, Throwable t) {
                if (t != null) {
                    span.setStatus(StatusCode.ERROR, t.getMessage());
                    span.recordException(t);
                    log.error("GraphQL execution failed", t);
                } else {
                    span.setStatus(StatusCode.OK);
                    if (result.getErrors() != null && !result.getErrors().isEmpty()) {
                        span.setAttribute("graphql.errors.count", result.getErrors().size());
                        log.warn("GraphQL execution completed with {} errors", result.getErrors().size());
                    }
                }
                
                state.getExecutionScope().close();
                span.end();
                log.debug("Completed GraphQL execution tracing for operation: {}", operationName);
            }
        };
    }

    @Override
    public InstrumentationContext<List<ValidationError>> beginValidation(
            InstrumentationValidationParameters parameters) {
        
        Span span = tracer.spanBuilder("graphql.validation")
            .setAttribute("graphql.document", parameters.getDocument().toString())
            .startSpan();
        
        Scope scope = span.makeCurrent();
        
        log.debug("Started GraphQL validation tracing");
        
        return new InstrumentationContext<List<ValidationError>>() {
            @Override
            public void onCompleted(List<ValidationError> result, Throwable t) {
                if (t != null) {
                    span.setStatus(StatusCode.ERROR, t.getMessage());
                    span.recordException(t);
                    log.error("GraphQL validation failed", t);
                } else {
                    span.setStatus(StatusCode.OK);
                    if (result != null && !result.isEmpty()) {
                        span.setAttribute("graphql.validation.errors.count", result.size());
                        log.warn("GraphQL validation completed with {} errors", result.size());
                    }
                }
                
                scope.close();
                span.end();
                log.debug("Completed GraphQL validation tracing");
            }
        };
    }

    @Override
    public ExecutionStrategyInstrumentationContext beginExecutionStrategy(
            InstrumentationExecutionStrategyParameters parameters) {
        
        String strategyName = parameters.getExecutionStrategyType().getSimpleName();
        
        Span span = tracer.spanBuilder("graphql.execution.strategy")
            .setAttribute("graphql.execution.strategy", strategyName)
            .startSpan();
        
        Scope scope = span.makeCurrent();
        
        log.debug("Started GraphQL execution strategy tracing: {}", strategyName);
        
        return new ExecutionStrategyInstrumentationContext() {
            @Override
            public void onCompleted(ExecutionResult result, Throwable t) {
                if (t != null) {
                    span.setStatus(StatusCode.ERROR, t.getMessage());
                    span.recordException(t);
                    log.error("GraphQL execution strategy failed: {}", strategyName, t);
                } else {
                    span.setStatus(StatusCode.OK);
                }
                
                scope.close();
                span.end();
                log.debug("Completed GraphQL execution strategy tracing: {}", strategyName);
            }
        };
    }

    @Override
    public InstrumentationContext<Object> beginFieldFetch(
            InstrumentationFieldFetchParameters parameters) {
        
        String fieldName = parameters.getField().getName();
        String typeName = parameters.getFieldType().getName();
        
        Span span = tracer.spanBuilder("graphql.field.fetch")
            .setAttribute("graphql.field.name", fieldName)
            .setAttribute("graphql.field.type", typeName)
            .setAttribute("graphql.field.path", parameters.getPath().toString())
            .startSpan();
        
        Scope scope = span.makeCurrent();
        
        log.debug("Started GraphQL field fetch tracing: {}.{}", typeName, fieldName);
        
        return new InstrumentationContext<Object>() {
            @Override
            public void onCompleted(Object result, Throwable t) {
                if (t != null) {
                    span.setStatus(StatusCode.ERROR, t.getMessage());
                    span.recordException(t);
                    log.error("GraphQL field fetch failed: {}.{}", typeName, fieldName, t);
                } else {
                    span.setStatus(StatusCode.OK);
                    if (result instanceof CompletableFuture) {
                        span.setAttribute("graphql.field.async", true);
                    }
                }
                
                scope.close();
                span.end();
                log.debug("Completed GraphQL field fetch tracing: {}.{}", typeName, fieldName);
            }
        };
    }

    @Override
    public DataFetcher<?> instrumentDataFetcher(
            DataFetcher<?> dataFetcher, 
            InstrumentationFieldFetchParameters parameters) {
        
        String fieldName = parameters.getField().getName();
        String typeName = parameters.getFieldType().getName();
        
        return environment -> {
            Span span = tracer.spanBuilder("graphql.data.fetcher")
                .setAttribute("graphql.field.name", fieldName)
                .setAttribute("graphql.field.type", typeName)
                .setAttribute("graphql.field.coordinates", typeName + "." + fieldName)
                .startSpan();
            
            try (Scope scope = span.makeCurrent()) {
                log.debug("Executing data fetcher: {}.{}", typeName, fieldName);
                
                Object result = dataFetcher.get(environment);
                
                if (result instanceof CompletableFuture) {
                    CompletableFuture<?> future = (CompletableFuture<?>) result;
                    return future.whenComplete((value, throwable) -> {
                        if (throwable != null) {
                            span.setStatus(StatusCode.ERROR, throwable.getMessage());
                            span.recordException(throwable);
                            log.error("Data fetcher failed: {}.{}", typeName, fieldName, throwable);
                        } else {
                            span.setStatus(StatusCode.OK);
                            log.debug("Data fetcher completed: {}.{}", typeName, fieldName);
                        }
                        span.end();
                    });
                } else {
                    span.setStatus(StatusCode.OK);
                    span.end();
                    log.debug("Data fetcher completed: {}.{}", typeName, fieldName);
                    return result;
                }
            } catch (Exception e) {
                span.setStatus(StatusCode.ERROR, e.getMessage());
                span.recordException(e);
                span.end();
                log.error("Data fetcher failed: {}.{}", typeName, fieldName, e);
                throw e;
            }
        };
    }

    private String getOperationType(Document document) {
        if (document.getDefinitions().isEmpty()) {
            return "unknown";
        }
        
        return document.getDefinitions().get(0).getClass().getSimpleName();
    }

    private static class TracingInstrumentationState implements InstrumentationState {
        private Span executionSpan;
        private Scope executionScope;

        public Span getExecutionSpan() {
            return executionSpan;
        }

        public void setExecutionSpan(Span executionSpan) {
            this.executionSpan = executionSpan;
        }

        public Scope getExecutionScope() {
            return executionScope;
        }

        public void setExecutionScope(Scope executionScope) {
            this.executionScope = executionScope;
        }
    }
}