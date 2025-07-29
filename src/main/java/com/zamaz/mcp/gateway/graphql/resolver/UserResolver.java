package com.zamaz.mcp.gateway.graphql.resolver;

import com.zamaz.mcp.gateway.graphql.model.*;
import com.zamaz.mcp.gateway.graphql.input.*;
import com.zamaz.mcp.gateway.graphql.payload.*;
import com.zamaz.mcp.gateway.service.UserService;
import graphql.schema.DataFetcher;
import graphql.schema.DataFetchingEnvironment;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.concurrent.CompletableFuture;

/**
 * GraphQL resolver for User-related queries and mutations
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class UserResolver {

    private final UserService userService;

    /**
     * Get user by ID
     */
    public DataFetcher<CompletableFuture<User>> getUser = environment -> {
        String id = environment.getArgument("id");
        log.debug("Getting user with ID: {}", id);
        
        return userService.getUserById(id)
            .thenApply(user -> {
                log.debug("Retrieved user: {}", user.getName());
                return user;
            });
    };

    /**
     * Get users with pagination and filtering
     */
    public DataFetcher<CompletableFuture<UserConnection>> getUsers = environment -> {
        Integer first = environment.getArgument("first");
        String after = environment.getArgument("after");
        UserFilter filter = environment.getArgument("filter");
        
        log.debug("Getting users with first={}, after={}, filter={}", first, after, filter);
        
        return userService.getUsers(first, after, filter)
            .thenApply(connection -> {
                log.debug("Retrieved {} users", connection.getEdges().size());
                return connection;
            });
    };

    /**
     * Get user's organization
     */
    public DataFetcher<CompletableFuture<Organization>> getUserOrganization = environment -> {
        User user = environment.getSource();
        
        log.debug("Getting organization for user: {}", user.getId());
        
        return userService.getUserOrganization(user.getId())
            .thenApply(organization -> {
                log.debug("Retrieved organization {} for user {}", organization.getName(), user.getId());
                return organization;
            });
    };

    /**
     * Get user's debates
     */
    public DataFetcher<CompletableFuture<DebateConnection>> getUserDebates = environment -> {
        User user = environment.getSource();
        Integer first = environment.getArgument("first");
        String after = environment.getArgument("after");
        DebateFilter filter = environment.getArgument("filter");
        
        log.debug("Getting debates for user: {}", user.getId());
        
        return userService.getUserDebates(user.getId(), first, after, filter)
            .thenApply(connection -> {
                log.debug("Retrieved {} debates for user {}", connection.getEdges().size(), user.getId());
                return connection;
            });
    };

    /**
     * Get user's arguments
     */
    public DataFetcher<CompletableFuture<ArgumentConnection>> getUserArguments = environment -> {
        User user = environment.getSource();
        Integer first = environment.getArgument("first");
        String after = environment.getArgument("after");
        String debateId = environment.getArgument("debateId");
        
        log.debug("Getting arguments for user: {}", user.getId());
        
        return userService.getUserArguments(user.getId(), first, after, debateId)
            .thenApply(connection -> {
                log.debug("Retrieved {} arguments for user {}", connection.getEdges().size(), user.getId());
                return connection;
            });
    };

    /**
     * Get user's votes
     */
    public DataFetcher<CompletableFuture<VoteConnection>> getUserVotes = environment -> {
        User user = environment.getSource();
        Integer first = environment.getArgument("first");
        String after = environment.getArgument("after");
        String debateId = environment.getArgument("debateId");
        
        log.debug("Getting votes for user: {}", user.getId());
        
        return userService.getUserVotes(user.getId(), first, after, debateId)
            .thenApply(connection -> {
                log.debug("Retrieved {} votes for user {}", connection.getEdges().size(), user.getId());
                return connection;
            });
    };

    /**
     * Get user's profile
     */
    public DataFetcher<CompletableFuture<UserProfile>> getUserProfile = environment -> {
        User user = environment.getSource();
        
        log.debug("Getting profile for user: {}", user.getId());
        
        return userService.getUserProfile(user.getId())
            .thenApply(profile -> {
                log.debug("Retrieved profile for user {}: {} debates, {} arguments", 
                    user.getId(), profile.getTotalDebates(), profile.getTotalArguments());
                return profile;
            });
    };

    /**
     * Create new user
     */
    public DataFetcher<CompletableFuture<CreateUserPayload>> createUser = environment -> {
        CreateUserInput input = environment.getArgument("input");
        
        log.debug("Creating user with email: {}", input.getEmail());
        
        return userService.createUser(input)
            .thenApply(payload -> {
                if (payload.getUser() != null) {
                    log.info("Created user: {} with ID: {}", 
                        payload.getUser().getName(), payload.getUser().getId());
                } else {
                    log.warn("Failed to create user: {}", payload.getErrors());
                }
                return payload;
            });
    };

    /**
     * Update existing user
     */
    public DataFetcher<CompletableFuture<UpdateUserPayload>> updateUser = environment -> {
        UpdateUserInput input = environment.getArgument("input");
        
        log.debug("Updating user with ID: {}", input.getId());
        
        return userService.updateUser(input)
            .thenApply(payload -> {
                if (payload.getUser() != null) {
                    log.info("Updated user: {} with ID: {}", 
                        payload.getUser().getName(), payload.getUser().getId());
                } else {
                    log.warn("Failed to update user: {}", payload.getErrors());
                }
                return payload;
            });
    };

    /**
     * Delete user
     */
    public DataFetcher<CompletableFuture<DeleteUserPayload>> deleteUser = environment -> {
        String id = environment.getArgument("id");
        
        log.debug("Deleting user with ID: {}", id);
        
        return userService.deleteUser(id)
            .thenApply(payload -> {
                if (payload.getDeletedUserId() != null) {
                    log.info("Deleted user with ID: {}", payload.getDeletedUserId());
                } else {
                    log.warn("Failed to delete user: {}", payload.getErrors());
                }
                return payload;
            });
    };
}