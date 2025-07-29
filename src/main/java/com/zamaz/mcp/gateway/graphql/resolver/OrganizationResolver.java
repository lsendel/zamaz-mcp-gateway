package com.zamaz.mcp.gateway.graphql.resolver;

import com.zamaz.mcp.gateway.graphql.model.*;
import com.zamaz.mcp.gateway.graphql.input.*;
import com.zamaz.mcp.gateway.graphql.payload.*;
import com.zamaz.mcp.gateway.service.OrganizationService;
import graphql.schema.DataFetcher;
import graphql.schema.DataFetchingEnvironment;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * GraphQL resolver for Organization-related queries and mutations
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class OrganizationResolver {

    private final OrganizationService organizationService;

    /**
     * Get organization by ID
     */
    public DataFetcher<CompletableFuture<Organization>> getOrganization = environment -> {
        String id = environment.getArgument("id");
        log.debug("Getting organization with ID: {}", id);
        
        return organizationService.getOrganizationById(id)
            .thenApply(org -> {
                log.debug("Retrieved organization: {}", org.getName());
                return org;
            });
    };

    /**
     * Get organizations with pagination and filtering
     */
    public DataFetcher<CompletableFuture<OrganizationConnection>> getOrganizations = environment -> {
        Integer first = environment.getArgument("first");
        String after = environment.getArgument("after");
        OrganizationFilter filter = environment.getArgument("filter");
        
        log.debug("Getting organizations with first={}, after={}, filter={}", first, after, filter);
        
        return organizationService.getOrganizations(first, after, filter)
            .thenApply(connection -> {
                log.debug("Retrieved {} organizations", connection.getEdges().size());
                return connection;
            });
    };

    /**
     * Get users for an organization
     */
    public DataFetcher<CompletableFuture<UserConnection>> getOrganizationUsers = environment -> {
        Organization organization = environment.getSource();
        Integer first = environment.getArgument("first");
        String after = environment.getArgument("after");
        UserFilter filter = environment.getArgument("filter");
        
        log.debug("Getting users for organization: {}", organization.getId());
        
        return organizationService.getOrganizationUsers(organization.getId(), first, after, filter)
            .thenApply(connection -> {
                log.debug("Retrieved {} users for organization {}", connection.getEdges().size(), organization.getId());
                return connection;
            });
    };

    /**
     * Get debates for an organization
     */
    public DataFetcher<CompletableFuture<DebateConnection>> getOrganizationDebates = environment -> {
        Organization organization = environment.getSource();
        Integer first = environment.getArgument("first");
        String after = environment.getArgument("after");
        DebateFilter filter = environment.getArgument("filter");
        
        log.debug("Getting debates for organization: {}", organization.getId());
        
        return organizationService.getOrganizationDebates(organization.getId(), first, after, filter)
            .thenApply(connection -> {
                log.debug("Retrieved {} debates for organization {}", connection.getEdges().size(), organization.getId());
                return connection;
            });
    };

    /**
     * Get statistics for an organization
     */
    public DataFetcher<CompletableFuture<OrganizationStatistics>> getOrganizationStats = environment -> {
        Organization organization = environment.getSource();
        
        log.debug("Getting statistics for organization: {}", organization.getId());
        
        return organizationService.getOrganizationStatistics(organization.getId())
            .thenApply(stats -> {
                log.debug("Retrieved statistics for organization {}: {} users, {} debates", 
                    organization.getId(), stats.getTotalUsers(), stats.getTotalDebates());
                return stats;
            });
    };

    /**
     * Create new organization
     */
    public DataFetcher<CompletableFuture<CreateOrganizationPayload>> createOrganization = environment -> {
        CreateOrganizationInput input = environment.getArgument("input");
        
        log.debug("Creating organization with name: {}", input.getName());
        
        return organizationService.createOrganization(input)
            .thenApply(payload -> {
                if (payload.getOrganization() != null) {
                    log.info("Created organization: {} with ID: {}", 
                        payload.getOrganization().getName(), payload.getOrganization().getId());
                } else {
                    log.warn("Failed to create organization: {}", payload.getErrors());
                }
                return payload;
            });
    };

    /**
     * Update existing organization
     */
    public DataFetcher<CompletableFuture<UpdateOrganizationPayload>> updateOrganization = environment -> {
        UpdateOrganizationInput input = environment.getArgument("input");
        
        log.debug("Updating organization with ID: {}", input.getId());
        
        return organizationService.updateOrganization(input)
            .thenApply(payload -> {
                if (payload.getOrganization() != null) {
                    log.info("Updated organization: {} with ID: {}", 
                        payload.getOrganization().getName(), payload.getOrganization().getId());
                } else {
                    log.warn("Failed to update organization: {}", payload.getErrors());
                }
                return payload;
            });
    };

    /**
     * Delete organization
     */
    public DataFetcher<CompletableFuture<DeleteOrganizationPayload>> deleteOrganization = environment -> {
        String id = environment.getArgument("id");
        
        log.debug("Deleting organization with ID: {}", id);
        
        return organizationService.deleteOrganization(id)
            .thenApply(payload -> {
                if (payload.getDeletedOrganizationId() != null) {
                    log.info("Deleted organization with ID: {}", payload.getDeletedOrganizationId());
                } else {
                    log.warn("Failed to delete organization: {}", payload.getErrors());
                }
                return payload;
            });
    };
}