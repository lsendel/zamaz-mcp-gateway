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
import graphql.validation.ValidationError;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * GraphQL instrumentation for metrics collection
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class MetricsInstrumentation extends SimpleInstrumentation {

    private final MeterRegistry meterRegistry;

    // Counters
    private final Counter executionCounter = Counter.builder("graphql.execution.total")
        .description("Total number of GraphQL executions")
        .register(meterRegistry);

    private final Counter errorCounter = Counter.builder("graphql.execution.errors")
        .description("Number of GraphQL execution errors")
        .register(meterRegistry);

    private final Counter validationErrorCounter = Counter.builder("graphql.validation.errors")
        .description("Number of GraphQL validation errors")
        .register(meterRegistry);

    private final Counter fieldFetchCounter = Counter.builder("graphql.field.fetch.total")
        .description("Total number of GraphQL field fetches")
        .register(meterRegistry);

    private final Counter fieldFetchErrorCounter = Counter.builder("graphql.field.fetch.errors")
        .description("Number of GraphQL field fetch errors")
        .register(meterRegistry);

    // Timers
    private final Timer executionTimer = Timer.builder("graphql.execution.duration")
        .description("GraphQL execution duration")
        .register(meterRegistry);

    private final Timer validationTimer = Timer.builder("graphql.validation.duration")
        .description("GraphQL validation duration")
        .register(meterRegistry);

    private final Timer fieldFetchTimer = Timer.builder("graphql.field.fetch.duration")
        .description("GraphQL field fetch duration")
        .register(meterRegistry);

    @Override
    public InstrumentationState createState() {
        return new MetricsInstrumentationState();
    }

    @Override
    public InstrumentationContext<ExecutionResult> beginExecution(
            InstrumentationExecutionParameters parameters) {
        
        MetricsInstrumentationState state = parameters.getInstrumentationState();
        
        String operationName = parameters.getOperation() != null ? 
            parameters.getOperation() : "unknown";
        String operationType = getOperationType(parameters.getDocument());
        
        // Increment execution counter
        executionCounter.increment(
            "operation", operationName,
            "type", operationType
        );
        
        // Start execution timer
        Timer.Sample sample = Timer.start(meterRegistry);
        state.setExecutionSample(sample);
        
        log.debug("Started GraphQL execution metrics for operation: {}", operationName);
        
        return new InstrumentationContext<ExecutionResult>() {
            @Override
            public void onCompleted(ExecutionResult result, Throwable t) {
                // Stop execution timer
                sample.stop(executionTimer.withTags(
                    "operation", operationName,
                    "type", operationType,
                    "status", t != null ? "error" : "success"
                ));
                
                if (t != null) {
                    // Increment error counter
                    errorCounter.increment(
                        "operation", operationName,
                        "type", operationType,
                        "error", t.getClass().getSimpleName()
                    );
                    log.error("GraphQL execution failed for operation: {}", operationName, t);
                } else if (result.getErrors() != null && !result.getErrors().isEmpty()) {
                    // Increment error counter for GraphQL errors
                    errorCounter.increment(
                        "operation", operationName,
                        "type", operationType,
                        "error", "GraphQLError"
                    );
                    log.warn("GraphQL execution completed with {} errors for operation: {}", 
                        result.getErrors().size(), operationName);
                }
                
                log.debug("Completed GraphQL execution metrics for operation: {}", operationName);
            }
        };
    }

    @Override
    public InstrumentationContext<List<ValidationError>> beginValidation(
            InstrumentationValidationParameters parameters) {
        
        // Start validation timer
        Timer.Sample sample = Timer.start(meterRegistry);
        
        log.debug("Started GraphQL validation metrics");
        
        return new InstrumentationContext<List<ValidationError>>() {
            @Override
            public void onCompleted(List<ValidationError> result, Throwable t) {
                // Stop validation timer
                sample.stop(validationTimer.withTags(
                    "status", t != null ? "error" : "success"
                ));
                
                if (t != null) {
                    validationErrorCounter.increment("error", t.getClass().getSimpleName());
                    log.error("GraphQL validation failed", t);
                } else if (result != null && !result.isEmpty()) {
                    validationErrorCounter.increment("error", "ValidationError");
                    log.warn("GraphQL validation completed with {} errors", result.size());
                }
                
                log.debug("Completed GraphQL validation metrics");
            }
        };
    }

    @Override
    public ExecutionStrategyInstrumentationContext beginExecutionStrategy(
            InstrumentationExecutionStrategyParameters parameters) {
        
        String strategyName = parameters.getExecutionStrategyType().getSimpleName();
        Timer.Sample sample = Timer.start(meterRegistry);
        
        log.debug("Started GraphQL execution strategy metrics: {}", strategyName);
        
        return new ExecutionStrategyInstrumentationContext() {
            @Override
            public void onCompleted(ExecutionResult result, Throwable t) {
                sample.stop(Timer.builder("graphql.execution.strategy.duration")
                    .description("GraphQL execution strategy duration")
                    .tag("strategy", strategyName)
                    .tag("status", t != null ? "error" : "success")
                    .register(meterRegistry));
                
                if (t != null) {
                    Counter.builder("graphql.execution.strategy.errors")
                        .description("GraphQL execution strategy errors")
                        .tag("strategy", strategyName)
                        .tag("error", t.getClass().getSimpleName())
                        .register(meterRegistry)
                        .increment();
                    log.error("GraphQL execution strategy failed: {}", strategyName, t);
                }
                
                log.debug("Completed GraphQL execution strategy metrics: {}", strategyName);
            }
        };
    }

    @Override
    public InstrumentationContext<Object> beginFieldFetch(
            InstrumentationFieldFetchParameters parameters) {
        
        String fieldName = parameters.getField().getName();
        String typeName = parameters.getFieldType().getName();
        String coordinates = typeName + "." + fieldName;
        
        // Increment field fetch counter
        fieldFetchCounter.increment(
            "field", coordinates,
            "type", typeName
        );
        
        // Start field fetch timer
        Timer.Sample sample = Timer.start(meterRegistry);
        
        log.debug("Started GraphQL field fetch metrics: {}", coordinates);
        
        return new InstrumentationContext<Object>() {
            @Override
            public void onCompleted(Object result, Throwable t) {
                // Stop field fetch timer
                sample.stop(fieldFetchTimer.withTags(
                    "field", coordinates,
                    "type", typeName,
                    "status", t != null ? "error" : "success"
                ));
                
                if (t != null) {
                    // Increment field fetch error counter
                    fieldFetchErrorCounter.increment(
                        "field", coordinates,
                        "type", typeName,
                        "error", t.getClass().getSimpleName()
                    );
                    log.error("GraphQL field fetch failed: {}", coordinates, t);
                }
                
                log.debug("Completed GraphQL field fetch metrics: {}", coordinates);
            }
        };
    }

    private String getOperationType(Document document) {
        if (document.getDefinitions().isEmpty()) {
            return "unknown";
        }
        
        return document.getDefinitions().get(0).getClass().getSimpleName();
    }

    private static class MetricsInstrumentationState implements InstrumentationState {
        private Timer.Sample executionSample;

        public Timer.Sample getExecutionSample() {
            return executionSample;
        }

        public void setExecutionSample(Timer.Sample executionSample) {
            this.executionSample = executionSample;
        }
    }
}