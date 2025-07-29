package com.zamaz.mcp.gateway.graphql.resolver;

import com.zamaz.mcp.gateway.graphql.model.*;
import com.zamaz.mcp.gateway.graphql.input.*;
import com.zamaz.mcp.gateway.graphql.payload.*;
import com.zamaz.mcp.gateway.service.DebateService;
import graphql.schema.DataFetcher;
import graphql.schema.DataFetchingEnvironment;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.reactivestreams.Publisher;

import java.util.concurrent.CompletableFuture;

/**
 * GraphQL resolver for Debate-related queries, mutations, and subscriptions
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DebateResolver {

    private final DebateService debateService;

    /**
     * Get debate by ID
     */
    public DataFetcher<CompletableFuture<Debate>> getDebate = environment -> {
        String id = environment.getArgument("id");
        log.debug("Getting debate with ID: {}", id);
        
        return debateService.getDebateById(id)
            .thenApply(debate -> {
                log.debug("Retrieved debate: {}", debate.getTitle());
                return debate;
            });
    };

    /**
     * Get debates with pagination and filtering
     */
    public DataFetcher<CompletableFuture<DebateConnection>> getDebates = environment -> {
        Integer first = environment.getArgument("first");
        String after = environment.getArgument("after");
        DebateFilter filter = environment.getArgument("filter");
        
        log.debug("Getting debates with first={}, after={}, filter={}", first, after, filter);
        
        return debateService.getDebates(first, after, filter)
            .thenApply(connection -> {
                log.debug("Retrieved {} debates", connection.getEdges().size());
                return connection;
            });
    };

    /**
     * Search debates
     */
    public DataFetcher<CompletableFuture<DebateConnection>> searchDebates = environment -> {
        String query = environment.getArgument("query");
        Integer first = environment.getArgument("first");
        String after = environment.getArgument("after");
        
        log.debug("Searching debates with query: {}", query);
        
        return debateService.searchDebates(query, first, after)
            .thenApply(connection -> {
                log.debug("Found {} debates for query: {}", connection.getEdges().size(), query);
                return connection;
            });
    };

    /**
     * Get debate statistics
     */
    public DataFetcher<CompletableFuture<DebateStatistics>> getDebateStats = environment -> {
        String organizationId = environment.getArgument("organizationId");
        TimeRange timeRange = environment.getArgument("timeRange");
        
        log.debug("Getting debate statistics for organization: {}, timeRange: {}", organizationId, timeRange);
        
        return debateService.getDebateStatistics(organizationId, timeRange)
            .thenApply(stats -> {
                log.debug("Retrieved statistics: {} total debates, {} active debates", 
                    stats.getTotalDebates(), stats.getActiveDebates());
                return stats;
            });
    };

    /**
     * Get debate's organization
     */
    public DataFetcher<CompletableFuture<Organization>> getDebateOrganization = environment -> {
        Debate debate = environment.getSource();
        
        log.debug("Getting organization for debate: {}", debate.getId());
        
        return debateService.getDebateOrganization(debate.getId())
            .thenApply(organization -> {
                log.debug("Retrieved organization {} for debate {}", organization.getName(), debate.getId());
                return organization;
            });
    };

    /**
     * Get debate participants
     */
    public DataFetcher<CompletableFuture<UserConnection>> getDebateParticipants = environment -> {
        Debate debate = environment.getSource();
        Integer first = environment.getArgument("first");
        String after = environment.getArgument("after");
        
        log.debug("Getting participants for debate: {}", debate.getId());
        
        return debateService.getDebateParticipants(debate.getId(), first, after)
            .thenApply(connection -> {
                log.debug("Retrieved {} participants for debate {}", connection.getEdges().size(), debate.getId());
                return connection;
            });
    };

    /**
     * Get debate arguments
     */
    public DataFetcher<CompletableFuture<ArgumentConnection>> getDebateArguments = environment -> {
        Debate debate = environment.getSource();
        Integer first = environment.getArgument("first");
        String after = environment.getArgument("after");
        ArgumentType type = environment.getArgument("type");
        String parentId = environment.getArgument("parentId");
        
        log.debug("Getting arguments for debate: {}", debate.getId());
        
        return debateService.getDebateArguments(debate.getId(), first, after, type, parentId)
            .thenApply(connection -> {
                log.debug("Retrieved {} arguments for debate {}", connection.getEdges().size(), debate.getId());
                return connection;
            });
    };

    /**
     * Get debate votes
     */
    public DataFetcher<CompletableFuture<VoteConnection>> getDebateVotes = environment -> {
        Debate debate = environment.getSource();
        Integer first = environment.getArgument("first");
        String after = environment.getArgument("after");
        VoteType type = environment.getArgument("type");
        
        log.debug("Getting votes for debate: {}", debate.getId());
        
        return debateService.getDebateVotes(debate.getId(), first, after, type)
            .thenApply(connection -> {
                log.debug("Retrieved {} votes for debate {}", connection.getEdges().size(), debate.getId());
                return connection;
            });
    };

    /**
     * Get debate statistics
     */
    public DataFetcher<CompletableFuture<DebateStats>> getDebateStatistics = environment -> {
        Debate debate = environment.getSource();
        
        log.debug("Getting statistics for debate: {}", debate.getId());
        
        return debateService.getDebateStats(debate.getId())
            .thenApply(stats -> {
                log.debug("Retrieved statistics for debate {}: {} participants, {} arguments", 
                    debate.getId(), stats.getParticipantCount(), stats.getArgumentCount());
                return stats;
            });
    };

    /**
     * Create new debate
     */
    public DataFetcher<CompletableFuture<CreateDebatePayload>> createDebate = environment -> {
        CreateDebateInput input = environment.getArgument("input");
        
        log.debug("Creating debate with title: {}", input.getTitle());
        
        return debateService.createDebate(input)
            .thenApply(payload -> {
                if (payload.getDebate() != null) {
                    log.info("Created debate: {} with ID: {}", 
                        payload.getDebate().getTitle(), payload.getDebate().getId());
                } else {
                    log.warn("Failed to create debate: {}", payload.getErrors());
                }
                return payload;
            });
    };

    /**
     * Update existing debate
     */
    public DataFetcher<CompletableFuture<UpdateDebatePayload>> updateDebate = environment -> {
        UpdateDebateInput input = environment.getArgument("input");
        
        log.debug("Updating debate with ID: {}", input.getId());
        
        return debateService.updateDebate(input)
            .thenApply(payload -> {
                if (payload.getDebate() != null) {
                    log.info("Updated debate: {} with ID: {}", 
                        payload.getDebate().getTitle(), payload.getDebate().getId());
                } else {
                    log.warn("Failed to update debate: {}", payload.getErrors());
                }
                return payload;
            });
    };

    /**
     * Delete debate
     */
    public DataFetcher<CompletableFuture<DeleteDebatePayload>> deleteDebate = environment -> {
        String id = environment.getArgument("id");
        
        log.debug("Deleting debate with ID: {}", id);
        
        return debateService.deleteDebate(id)
            .thenApply(payload -> {
                if (payload.getDeletedDebateId() != null) {
                    log.info("Deleted debate with ID: {}", payload.getDeletedDebateId());
                } else {
                    log.warn("Failed to delete debate: {}", payload.getErrors());
                }
                return payload;
            });
    };

    /**
     * Join debate
     */
    public DataFetcher<CompletableFuture<JoinDebatePayload>> joinDebate = environment -> {
        String debateId = environment.getArgument("debateId");
        
        log.debug("Joining debate with ID: {}", debateId);
        
        return debateService.joinDebate(debateId)
            .thenApply(payload -> {
                if (payload.getDebate() != null) {
                    log.info("User joined debate: {}", payload.getDebate().getId());
                } else {
                    log.warn("Failed to join debate: {}", payload.getErrors());
                }
                return payload;
            });
    };

    /**
     * Leave debate
     */
    public DataFetcher<CompletableFuture<LeaveDebatePayload>> leaveDebate = environment -> {
        String debateId = environment.getArgument("debateId");
        
        log.debug("Leaving debate with ID: {}", debateId);
        
        return debateService.leaveDebate(debateId)
            .thenApply(payload -> {
                if (payload.getDebate() != null) {
                    log.info("User left debate: {}", payload.getDebate().getId());
                } else {
                    log.warn("Failed to leave debate: {}", payload.getErrors());
                }
                return payload;
            });
    };

    /**
     * Submit argument
     */
    public DataFetcher<CompletableFuture<SubmitArgumentPayload>> submitArgument = environment -> {
        SubmitArgumentInput input = environment.getArgument("input");
        
        log.debug("Submitting argument for debate: {}", input.getDebateId());
        
        return debateService.submitArgument(input)
            .thenApply(payload -> {
                if (payload.getArgument() != null) {
                    log.info("Submitted argument with ID: {}", payload.getArgument().getId());
                } else {
                    log.warn("Failed to submit argument: {}", payload.getErrors());
                }
                return payload;
            });
    };

    /**
     * Vote on argument
     */
    public DataFetcher<CompletableFuture<VoteOnArgumentPayload>> voteOnArgument = environment -> {
        VoteOnArgumentInput input = environment.getArgument("input");
        
        log.debug("Voting on argument: {}", input.getArgumentId());
        
        return debateService.voteOnArgument(input)
            .thenApply(payload -> {
                if (payload.getVote() != null) {
                    log.info("Voted on argument: {} with vote: {}", 
                        input.getArgumentId(), payload.getVote().getVoteType());
                } else {
                    log.warn("Failed to vote on argument: {}", payload.getErrors());
                }
                return payload;
            });
    };

    // Subscription resolvers
    
    /**
     * Subscribe to debate updates
     */
    public DataFetcher<Publisher<DebateUpdatePayload>> debateUpdates = environment -> {
        String debateId = environment.getArgument("debateId");
        
        log.debug("Subscribing to updates for debate: {}", debateId);
        
        return debateService.subscribeToDebateUpdates(debateId);
    };

    /**
     * Subscribe to argument additions
     */
    public DataFetcher<Publisher<ArgumentAddedPayload>> argumentAdded = environment -> {
        String debateId = environment.getArgument("debateId");
        
        log.debug("Subscribing to argument additions for debate: {}", debateId);
        
        return debateService.subscribeToArgumentAdditions(debateId);
    };

    /**
     * Subscribe to user joins
     */
    public DataFetcher<Publisher<UserJoinedPayload>> userJoined = environment -> {
        String debateId = environment.getArgument("debateId");
        
        log.debug("Subscribing to user joins for debate: {}", debateId);
        
        return debateService.subscribeToUserJoins(debateId);
    };

    /**
     * Subscribe to user leaves
     */
    public DataFetcher<Publisher<UserLeftPayload>> userLeft = environment -> {
        String debateId = environment.getArgument("debateId");
        
        log.debug("Subscribing to user leaves for debate: {}", debateId);
        
        return debateService.subscribeToUserLeaves(debateId);
    };

    /**
     * Subscribe to vote updates
     */
    public DataFetcher<Publisher<VoteUpdatedPayload>> voteUpdated = environment -> {
        String debateId = environment.getArgument("debateId");
        
        log.debug("Subscribing to vote updates for debate: {}", debateId);
        
        return debateService.subscribeToVoteUpdates(debateId);
    };
}