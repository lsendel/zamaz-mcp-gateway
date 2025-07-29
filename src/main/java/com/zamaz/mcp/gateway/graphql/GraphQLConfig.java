package com.zamaz.mcp.gateway.graphql;

import com.zamaz.mcp.gateway.graphql.resolver.DebateResolver;
import com.zamaz.mcp.gateway.graphql.resolver.OrganizationResolver;
import com.zamaz.mcp.gateway.graphql.resolver.UserResolver;
import com.zamaz.mcp.gateway.graphql.scalar.DateTimeScalar;
import com.zamaz.mcp.gateway.graphql.scalar.JsonScalar;
import com.zamaz.mcp.gateway.graphql.directive.AuthDirective;
import com.zamaz.mcp.gateway.graphql.directive.RateLimitDirective;
import com.zamaz.mcp.gateway.graphql.directive.ValidateDirective;
import com.zamaz.mcp.gateway.graphql.instrumentation.TracingInstrumentation;
import com.zamaz.mcp.gateway.graphql.instrumentation.MetricsInstrumentation;
import com.zamaz.mcp.gateway.graphql.security.GraphQLSecurityService;
import graphql.GraphQL;
import graphql.execution.AsyncExecutionStrategy;
import graphql.execution.DataFetcherExceptionHandler;
import graphql.execution.SimpleDataFetcherExceptionHandler;
import graphql.execution.instrumentation.ChainedInstrumentation;
import graphql.execution.instrumentation.Instrumentation;
import graphql.execution.instrumentation.dataloader.DataLoaderDispatcherInstrumentation;
import graphql.execution.instrumentation.tracing.TracingInstrumentation.Options;
import graphql.kickstart.execution.GraphQLQueryInvoker;
import graphql.kickstart.execution.config.GraphQLSchemaProvider;
import graphql.kickstart.servlet.GraphQLHttpServlet;
import graphql.kickstart.servlet.GraphQLWebsocketServlet;
import graphql.schema.GraphQLSchema;
import graphql.schema.idl.RuntimeWiring;
import graphql.schema.idl.SchemaGenerator;
import graphql.schema.idl.SchemaParser;
import graphql.schema.idl.TypeDefinitionRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;

/**
 * GraphQL Configuration for MCP Gateway
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class GraphQLConfig implements WebMvcConfigurer {

    private final OrganizationResolver organizationResolver;
    private final UserResolver userResolver;
    private final DebateResolver debateResolver;
    private final GraphQLSecurityService securityService;
    private final TracingInstrumentation tracingInstrumentation;
    private final MetricsInstrumentation metricsInstrumentation;

    /**
     * GraphQL Schema configuration
     */
    @Bean
    public GraphQLSchema graphQLSchema() throws IOException {
        // Load schema files
        TypeDefinitionRegistry typeRegistry = new TypeDefinitionRegistry();
        
        // Load main schema
        SchemaParser schemaParser = new SchemaParser();
        typeRegistry.merge(schemaParser.parse(
            new InputStreamReader(new ClassPathResource("graphql/schema.graphqls").getInputStream())
        ));
        
        // Load type definitions
        typeRegistry.merge(schemaParser.parse(
            new InputStreamReader(new ClassPathResource("graphql/types.graphqls").getInputStream())
        ));
        
        // Load mutations
        typeRegistry.merge(schemaParser.parse(
            new InputStreamReader(new ClassPathResource("graphql/mutations.graphqls").getInputStream())
        ));
        
        // Load subscriptions
        typeRegistry.merge(schemaParser.parse(
            new InputStreamReader(new ClassPathResource("graphql/subscriptions.graphqls").getInputStream())
        ));

        // Build runtime wiring
        RuntimeWiring runtimeWiring = buildRuntimeWiring();

        // Generate schema
        SchemaGenerator schemaGenerator = new SchemaGenerator();
        return schemaGenerator.makeExecutableSchema(typeRegistry, runtimeWiring);
    }

    /**
     * Build runtime wiring with resolvers and directives
     */
    private RuntimeWiring buildRuntimeWiring() {
        return RuntimeWiring.newRuntimeWiring()
            // Queries
            .type("Query", builder -> builder
                .dataFetcher("organization", organizationResolver::getOrganization)
                .dataFetcher("organizations", organizationResolver::getOrganizations)
                .dataFetcher("user", userResolver::getUser)
                .dataFetcher("users", userResolver::getUsers)
                .dataFetcher("debate", debateResolver::getDebate)
                .dataFetcher("debates", debateResolver::getDebates)
                .dataFetcher("debateStats", debateResolver::getDebateStats)
                .dataFetcher("searchDebates", debateResolver::searchDebates)
            )
            // Mutations
            .type("Mutation", builder -> builder
                .dataFetcher("createOrganization", organizationResolver::createOrganization)
                .dataFetcher("updateOrganization", organizationResolver::updateOrganization)
                .dataFetcher("deleteOrganization", organizationResolver::deleteOrganization)
                .dataFetcher("createUser", userResolver::createUser)
                .dataFetcher("updateUser", userResolver::updateUser)
                .dataFetcher("deleteUser", userResolver::deleteUser)
                .dataFetcher("createDebate", debateResolver::createDebate)
                .dataFetcher("updateDebate", debateResolver::updateDebate)
                .dataFetcher("deleteDebate", debateResolver::deleteDebate)
                .dataFetcher("joinDebate", debateResolver::joinDebate)
                .dataFetcher("leaveDebate", debateResolver::leaveDebate)
                .dataFetcher("submitArgument", debateResolver::submitArgument)
                .dataFetcher("voteOnArgument", debateResolver::voteOnArgument)
            )
            // Subscriptions
            .type("Subscription", builder -> builder
                .dataFetcher("debateUpdates", debateResolver::debateUpdates)
                .dataFetcher("argumentAdded", debateResolver::argumentAdded)
                .dataFetcher("userJoined", debateResolver::userJoined)
                .dataFetcher("userLeft", debateResolver::userLeft)
                .dataFetcher("voteUpdated", debateResolver::voteUpdated)
            )
            // Nested type resolvers
            .type("Organization", builder -> builder
                .dataFetcher("users", organizationResolver::getOrganizationUsers)
                .dataFetcher("debates", organizationResolver::getOrganizationDebates)
                .dataFetcher("stats", organizationResolver::getOrganizationStats)
            )
            .type("User", builder -> builder
                .dataFetcher("organization", userResolver::getUserOrganization)
                .dataFetcher("debates", userResolver::getUserDebates)
                .dataFetcher("arguments", userResolver::getUserArguments)
                .dataFetcher("votes", userResolver::getUserVotes)
            )
            .type("Debate", builder -> builder
                .dataFetcher("organization", debateResolver::getDebateOrganization)
                .dataFetcher("participants", debateResolver::getDebateParticipants)
                .dataFetcher("arguments", debateResolver::getDebateArguments)
                .dataFetcher("votes", debateResolver::getDebateVotes)
                .dataFetcher("stats", debateResolver::getDebateStatistics)
            )
            // Custom scalars
            .scalar(DateTimeScalar.INSTANCE)
            .scalar(JsonScalar.INSTANCE)
            // Directives
            .directive("auth", new AuthDirective(securityService))
            .directive("rateLimit", new RateLimitDirective())
            .directive("validate", new ValidateDirective())
            .build();
    }

    /**
     * GraphQL execution configuration
     */
    @Bean
    public GraphQL graphQL(GraphQLSchema schema) {
        return GraphQL.newGraphQL(schema)
            .queryExecutionStrategy(new AsyncExecutionStrategy(exceptionHandler()))
            .mutationExecutionStrategy(new AsyncExecutionStrategy(exceptionHandler()))
            .subscriptionExecutionStrategy(new AsyncExecutionStrategy(exceptionHandler()))
            .instrumentation(instrumentation())
            .build();
    }

    /**
     * Exception handler for GraphQL execution
     */
    private DataFetcherExceptionHandler exceptionHandler() {
        return new GraphQLExceptionHandler();
    }

    /**
     * Instrumentation chain for GraphQL execution
     */
    private Instrumentation instrumentation() {
        List<Instrumentation> instrumentations = Arrays.asList(
            tracingInstrumentation,
            metricsInstrumentation,
            new DataLoaderDispatcherInstrumentation()
        );
        return new ChainedInstrumentation(instrumentations);
    }

    /**
     * GraphQL HTTP servlet registration
     */
    @Bean
    public ServletRegistrationBean<GraphQLHttpServlet> graphQLServlet(GraphQL graphQL) {
        GraphQLHttpServlet servlet = GraphQLHttpServlet.with(graphQL)
            .with(new GraphQLSchemaProvider() {
                @Override
                public GraphQLSchema getSchema() {
                    try {
                        return graphQLSchema();
                    } catch (IOException e) {
                        throw new RuntimeException("Failed to load GraphQL schema", e);
                    }
                }

                @Override
                public GraphQLSchema getSchema(String schemaName) {
                    return getSchema();
                }
            })
            .with(new GraphQLQueryInvoker())
            .build();

        ServletRegistrationBean<GraphQLHttpServlet> registration = 
            new ServletRegistrationBean<>(servlet, "/graphql");
        registration.setLoadOnStartup(1);
        return registration;
    }

    /**
     * GraphQL WebSocket servlet registration for subscriptions
     */
    @Bean
    public ServletRegistrationBean<GraphQLWebsocketServlet> graphQLWebSocketServlet(GraphQL graphQL) {
        GraphQLWebsocketServlet servlet = GraphQLWebsocketServlet.with(graphQL)
            .with(new GraphQLSchemaProvider() {
                @Override
                public GraphQLSchema getSchema() {
                    try {
                        return graphQLSchema();
                    } catch (IOException e) {
                        throw new RuntimeException("Failed to load GraphQL schema", e);
                    }
                }

                @Override
                public GraphQLSchema getSchema(String schemaName) {
                    return getSchema();
                }
            })
            .build();

        ServletRegistrationBean<GraphQLWebsocketServlet> registration = 
            new ServletRegistrationBean<>(servlet, "/graphql-ws");
        registration.setLoadOnStartup(1);
        return registration;
    }

    /**
     * CORS configuration for GraphQL endpoints
     */
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/graphql/**")
            .allowedOrigins("*")
            .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
            .allowedHeaders("*")
            .allowCredentials(true)
            .maxAge(3600);
    }

    /**
     * Custom exception handler for GraphQL
     */
    private static class GraphQLExceptionHandler implements DataFetcherExceptionHandler {
        @Override
        public DataFetcherExceptionHandlerResult onException(DataFetcherExceptionHandlerParameters handlerParameters) {
            Throwable exception = handlerParameters.getException();
            log.error("GraphQL execution error", exception);
            
            return DataFetcherExceptionHandlerResult.newResult()
                .error(new GraphQLErrorAdapter(exception))
                .build();
        }
    }
}