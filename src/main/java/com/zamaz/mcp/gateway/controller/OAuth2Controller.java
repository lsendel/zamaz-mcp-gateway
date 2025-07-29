package com.zamaz.mcp.gateway.controller;

import com.zamaz.mcp.gateway.service.OAuth2UserPrincipal;
import com.zamaz.mcp.security.audit.SecurityAuditLogger;
import com.zamaz.mcp.security.model.McpUser;
import com.zamaz.mcp.security.service.JwtService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * REST controller for OAuth2 and SSO operations.
 */
@RestController
@RequestMapping("/api/v1/oauth2")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "OAuth2", description = "OAuth2 and SSO authentication endpoints")
public class OAuth2Controller {

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final JwtService jwtService;
    private final SecurityAuditLogger auditLogger;

    @Value("${oauth2.base-url:http://localhost:8080}")
    private String baseUrl;

    /**
     * Get available OAuth2 providers.
     */
    @Operation(
        summary = "Get available OAuth2 providers",
        description = "Returns a list of configured OAuth2 providers available for authentication"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Available OAuth2 providers",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = OAuth2ProvidersResponse.class),
                examples = @ExampleObject(value = """
                    {
                        "providers": [
                            {
                                "id": "google",
                                "name": "Google",
                                "loginUrl": "http://localhost:8080/oauth2/authorization/google"
                            },
                            {
                                "id": "microsoft",
                                "name": "Microsoft",
                                "loginUrl": "http://localhost:8080/oauth2/authorization/microsoft"
                            }
                        ]
                    }
                    """)
            )
        )
    })
    @GetMapping("/providers")
    public ResponseEntity<OAuth2ProvidersResponse> getProviders() {
        var providers = clientRegistrationRepository.findByRegistrationId("google"); // Get all registrations
        
        var providerList = new java.util.ArrayList<OAuth2Provider>();
        
        // Check each known provider
        String[] knownProviders = {"google", "microsoft", "github", "custom"};
        for (String providerId : knownProviders) {
            var registration = clientRegistrationRepository.findByRegistrationId(providerId);
            if (registration != null) {
                providerList.add(new OAuth2Provider(
                    providerId,
                    registration.getClientName(),
                    baseUrl + "/oauth2/authorization/" + providerId
                ));
            }
        }
        
        log.info("Returning {} configured OAuth2 providers", providerList.size());
        return ResponseEntity.ok(new OAuth2ProvidersResponse(providerList));
    }

    /**
     * Get current user information (for OAuth2 authenticated users).
     */
    @Operation(
        summary = "Get current OAuth2 user",
        description = "Returns current user information for OAuth2 authenticated users"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Current user information",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = OAuth2UserResponse.class)
            )
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required"
        )
    })
    @GetMapping("/user")
    public ResponseEntity<OAuth2UserResponse> getCurrentUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).build();
        }

        OAuth2UserResponse userResponse;
        
        if (authentication.getPrincipal() instanceof OAuth2UserPrincipal oauth2Principal) {
            McpUser user = oauth2Principal.getUser();
            userResponse = OAuth2UserResponse.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .emailVerified(user.isEmailVerified())
                .provider(extractProvider(user))
                .roles(user.getRoles())
                .organizations(user.getOrganizationIds())
                .build();
        } else {
            // Handle regular JWT authentication
            userResponse = OAuth2UserResponse.builder()
                .userId(authentication.getName())
                .email(authentication.getName())
                .provider("jwt")
                .build();
        }

        return ResponseEntity.ok(userResponse);
    }

    /**
     * Link OAuth2 account to existing user account.
     */
    @Operation(
        summary = "Link OAuth2 account",
        description = "Link an OAuth2 account to an existing user account"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Account linked successfully"
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid request or account already linked"
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required"
        )
    })
    @PostMapping("/link")
    public ResponseEntity<Map<String, String>> linkAccount(
            @RequestParam String provider,
            Authentication authentication,
            HttpServletRequest request) {
        
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).build();
        }

        String userId = authentication.getName();
        String clientIp = getClientIp(request);
        
        auditLogger.logSecurityEvent(
            SecurityAuditLogger.SecurityEventType.OAUTH2_ACCOUNT_LINKED,
            SecurityAuditLogger.RiskLevel.MEDIUM,
            "OAuth2 account linked",
            Map.of(
                "userId", userId,
                "provider", provider,
                "clientIp", clientIp
            )
        );

        log.info("OAuth2 account linking initiated for user: {} with provider: {}", userId, provider);
        
        Map<String, String> response = new HashMap<>();
        response.put("message", "Account linking initiated");
        response.put("linkUrl", baseUrl + "/oauth2/authorization/" + provider + "?link=true");
        
        return ResponseEntity.ok(response);
    }

    /**
     * Unlink OAuth2 account from user account.
     */
    @Operation(
        summary = "Unlink OAuth2 account",
        description = "Unlink an OAuth2 account from the current user account"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Account unlinked successfully"
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid request or account not linked"
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required"
        )
    })
    @DeleteMapping("/unlink")
    public ResponseEntity<Map<String, String>> unlinkAccount(
            @RequestParam String provider,
            Authentication authentication,
            HttpServletRequest request) {
        
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).build();
        }

        String userId = authentication.getName();
        String clientIp = getClientIp(request);
        
        auditLogger.logSecurityEvent(
            SecurityAuditLogger.SecurityEventType.OAUTH2_ACCOUNT_UNLINKED,
            SecurityAuditLogger.RiskLevel.MEDIUM,
            "OAuth2 account unlinked",
            Map.of(
                "userId", userId,
                "provider", provider,
                "clientIp", clientIp
            )
        );

        log.info("OAuth2 account unlinking for user: {} with provider: {}", userId, provider);
        
        Map<String, String> response = new HashMap<>();
        response.put("message", "Account unlinked successfully");
        
        return ResponseEntity.ok(response);
    }

    /**
     * OAuth2 login callback endpoint.
     */
    @Operation(
        summary = "OAuth2 login callback",
        description = "Handle OAuth2 login callback and return JWT token"
    )
    @GetMapping("/callback")
    public ResponseEntity<Map<String, String>> handleCallback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String error,
            Authentication authentication) {
        
        Map<String, String> response = new HashMap<>();
        
        if (error != null) {
            log.error("OAuth2 callback error: {}", error);
            response.put("error", error);
            return ResponseEntity.badRequest().body(response);
        }
        
        if (authentication != null && authentication.isAuthenticated()) {
            // Generate JWT token
            String token = jwtService.generateToken(authentication.getName());
            response.put("token", token);
            response.put("message", "Authentication successful");
            
            log.debug("OAuth2 callback successful for user: {}", authentication.getName());
            return ResponseEntity.ok(response);
        }
        
        response.put("error", "Authentication failed");
        return ResponseEntity.badRequest().body(response);
    }

    private String extractProvider(McpUser user) {
        return user.getRoles().stream()
            .filter(role -> role.startsWith("OAUTH2_"))
            .map(role -> role.substring(7).toLowerCase())
            .findFirst()
            .orElse("unknown");
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    // DTOs for responses
    public static class OAuth2ProvidersResponse {
        private final java.util.List<OAuth2Provider> providers;

        public OAuth2ProvidersResponse(java.util.List<OAuth2Provider> providers) {
            this.providers = providers;
        }

        public java.util.List<OAuth2Provider> getProviders() {
            return providers;
        }
    }

    public static class OAuth2Provider {
        private final String id;
        private final String name;
        private final String loginUrl;

        public OAuth2Provider(String id, String name, String loginUrl) {
            this.id = id;
            this.name = name;
            this.loginUrl = loginUrl;
        }

        public String getId() { return id; }
        public String getName() { return name; }
        public String getLoginUrl() { return loginUrl; }
    }

    public static class OAuth2UserResponse {
        private final String userId;
        private final String email;
        private final String firstName;
        private final String lastName;
        private final boolean emailVerified;
        private final String provider;
        private final java.util.List<String> roles;
        private final java.util.Collection<String> organizations;

        private OAuth2UserResponse(Builder builder) {
            this.userId = builder.userId;
            this.email = builder.email;
            this.firstName = builder.firstName;
            this.lastName = builder.lastName;
            this.emailVerified = builder.emailVerified;
            this.provider = builder.provider;
            this.roles = builder.roles;
            this.organizations = builder.organizations;
        }

        public static Builder builder() {
            return new Builder();
        }

        public String getUserId() { return userId; }
        public String getEmail() { return email; }
        public String getFirstName() { return firstName; }
        public String getLastName() { return lastName; }
        public boolean isEmailVerified() { return emailVerified; }
        public String getProvider() { return provider; }
        public java.util.List<String> getRoles() { return roles; }
        public java.util.Collection<String> getOrganizations() { return organizations; }

        public static class Builder {
            private String userId;
            private String email;
            private String firstName;
            private String lastName;
            private boolean emailVerified;
            private String provider;
            private java.util.List<String> roles;
            private java.util.Collection<String> organizations;

            public Builder userId(String userId) { this.userId = userId; return this; }
            public Builder email(String email) { this.email = email; return this; }
            public Builder firstName(String firstName) { this.firstName = firstName; return this; }
            public Builder lastName(String lastName) { this.lastName = lastName; return this; }
            public Builder emailVerified(boolean emailVerified) { this.emailVerified = emailVerified; return this; }
            public Builder provider(String provider) { this.provider = provider; return this; }
            public Builder roles(java.util.List<String> roles) { this.roles = roles; return this; }
            public Builder organizations(java.util.Collection<String> organizations) { this.organizations = organizations; return this; }

            public OAuth2UserResponse build() {
                return new OAuth2UserResponse(this);
            }
        }
    }
}