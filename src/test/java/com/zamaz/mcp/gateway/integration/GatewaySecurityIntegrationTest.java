package com.zamaz.mcp.gateway.integration;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Gateway Security Integration Tests
 * Tests the complete security filter chain in the gateway
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class GatewaySecurityIntegrationTest {

    @Autowired
    private WebTestClient webTestClient;

    @Test
    void testSecurityHeaders_ShouldBePresent() {
        webTestClient
            .get()
            .uri("/api/v1/auth/login")
            .exchange()
            .expectHeader().exists("X-Content-Type-Options")
            .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
            .expectHeader().exists("X-Frame-Options")
            .expectHeader().valueEquals("X-Frame-Options", "DENY")
            .expectHeader().exists("X-XSS-Protection")
            .expectHeader().exists("Referrer-Policy")
            .expectHeader().exists("Content-Security-Policy")
            .expectHeader().exists("X-Request-ID");
    }

    @Test
    void testCORS_ShouldRestrictOrigins() {
        webTestClient
            .options()
            .uri("/api/v1/test")
            .header("Origin", "http://malicious-site.com")
            .header("Access-Control-Request-Method", "GET")
            .exchange()
            .expectStatus().isForbidden();
    }

    @Test
    void testCORS_ShouldAllowLocalhostOrigins() {
        webTestClient
            .options()
            .uri("/api/v1/auth/login")
            .header("Origin", "http://localhost:3000")
            .header("Access-Control-Request-Method", "GET")
            .exchange()
            .expectStatus().isOk()
            .expectHeader().exists("Access-Control-Allow-Origin");
    }

    @Test
    void testMaliciousRequest_XSS_ShouldBeBlocked() {
        webTestClient
            .get()
            .uri("/api/v1/search?q=<script>alert('xss')</script>")
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody()
            .jsonPath("$.error").isEqualTo("Security Violation")
            .jsonPath("$.message").isEqualTo("Malicious content detected");
    }

    @Test
    void testMaliciousRequest_SQLInjection_ShouldBeBlocked() {
        webTestClient
            .get()
            .uri("/api/v1/users?id=1 OR 1=1")
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody()
            .jsonPath("$.error").isEqualTo("Security Violation");
    }

    @Test
    void testSuspiciousUserAgent_ShouldBeBlocked() {
        webTestClient
            .get()
            .uri("/api/v1/test")
            .header("User-Agent", "sqlmap/1.0")
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody()
            .jsonPath("$.error").isEqualTo("Security Violation")
            .jsonPath("$.message").isEqualTo("Suspicious user agent");
    }

    @Test
    void testUnsupportedHttpMethod_ShouldBeBlocked() {
        webTestClient
            .method(org.springframework.http.HttpMethod.TRACE)
            .uri("/api/v1/test")
            .exchange()
            .expectStatus().isBadRequest();
    }

    @Test
    void testAuthenticationRequired_ShouldReturn401() {
        webTestClient
            .get()
            .uri("/api/v1/protected")
            .exchange()
            .expectStatus().isUnauthorized()
            .expectBody()
            .jsonPath("$.error").isEqualTo("Unauthorized")
            .jsonPath("$.message").isEqualTo("Valid JWT token required");
    }

    @Test
    void testInvalidAuthToken_ShouldReturn401() {
        webTestClient
            .get()
            .uri("/api/v1/protected")
            .header("Authorization", "Bearer invalid.token.here")
            .exchange()
            .expectStatus().isUnauthorized();
    }

    @Test
    void testOpenEndpoints_ShouldNotRequireAuth() {
        webTestClient
            .get()
            .uri("/api/v1/auth/login")
            .exchange()
            .expectStatus().is2xxSuccessful();

        webTestClient
            .get()
            .uri("/health")
            .exchange()
            .expectStatus().is2xxSuccessful();

        webTestClient
            .get()
            .uri("/actuator/health")
            .exchange()
            .expectStatus().is2xxSuccessful();
    }

    @Test
    void testRateLimiting_ShouldHaveHeaders() {
        webTestClient
            .get()
            .uri("/api/v1/auth/login")
            .exchange()
            .expectHeader().exists("X-Rate-Limit-Limit");
    }

    @Test
    void testSecurityConfiguration_ComprehensiveCheck() {
        webTestClient
            .get()
            .uri("/api/v1/auth/login")
            .header("User-Agent", "Mozilla/5.0 (compatible test)")
            .exchange()
            .expectStatus().is2xxSuccessful()
            // Security headers
            .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
            .expectHeader().valueEquals("X-Frame-Options", "DENY")
            .expectHeader().exists("Content-Security-Policy")
            .expectHeader().exists("Referrer-Policy")
            .expectHeader().exists("Permissions-Policy")
            // Request tracking
            .expectHeader().exists("X-Request-ID")
            // Rate limiting
            .expectHeader().exists("X-Rate-Limit-Limit")
            // Cache control
            .expectHeader().valueEquals("Cache-Control", "no-cache, no-store, must-revalidate")
            .expectHeader().valueEquals("Pragma", "no-cache")
            .expectHeader().valueEquals("Expires", "0");
    }
}
