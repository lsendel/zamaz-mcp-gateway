package com.zamaz.mcp.gateway.filter;

import com.zamaz.mcp.security.jwt.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.URI;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Security Filter Tests for API Gateway
 */
@ExtendWith(MockitoExtension.class)
class SecurityFilterTests {

    @Mock
    private JwtTokenProvider jwtTokenProvider;
    
    @Mock
    private GatewayFilterChain filterChain;
    
    private AuthenticationFilter authenticationFilter;
    private SecurityHeadersFilter securityHeadersFilter;
    private RequestValidationFilter requestValidationFilter;
    
    @BeforeEach
    void setUp() {
        authenticationFilter = new AuthenticationFilter(jwtTokenProvider);
        securityHeadersFilter = new SecurityHeadersFilter();
        requestValidationFilter = new RequestValidationFilter();
        
        when(filterChain.filter(any(ServerWebExchange.class)))
            .thenReturn(Mono.empty());
    }
    
    @Test
    void testAuthenticationFilter_ValidToken_ShouldAllowRequest() {
        // Given
        String validToken = "valid.jwt.token";
        MockServerHttpRequest request = MockServerHttpRequest
            .get("/api/v1/protected")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken)
            .build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);
        
        when(jwtTokenProvider.validateToken(validToken)).thenReturn(true);
        when(jwtTokenProvider.getUserIdFromToken(validToken)).thenReturn("user123");
        when(jwtTokenProvider.getOrganizationIdFromToken(validToken)).thenReturn("org456");
        when(jwtTokenProvider.getRolesFromToken(validToken)).thenReturn(List.of("USER", "ADMIN"));
        
        // When
        GatewayFilter filter = authenticationFilter.apply(new AuthenticationFilter.Config());
        Mono<Void> result = filter.filter(exchange, filterChain);
        
        // Then
        StepVerifier.create(result)
            .verifyComplete();
            
        assertThat(exchange.getRequest().getHeaders().getFirst("X-User-ID")).isEqualTo("user123");
        assertThat(exchange.getRequest().getHeaders().getFirst("X-Organization-ID")).isEqualTo("org456");
        assertThat(exchange.getRequest().getHeaders().getFirst("X-User-Roles")).isEqualTo("USER,ADMIN");
    }
    
    @Test
    void testAuthenticationFilter_InvalidToken_ShouldRejectRequest() {
        // Given
        String invalidToken = "invalid.jwt.token";
        MockServerHttpRequest request = MockServerHttpRequest
            .get("/api/v1/protected")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + invalidToken)
            .build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);
        
        when(jwtTokenProvider.validateToken(invalidToken)).thenReturn(false);
        
        // When
        GatewayFilter filter = authenticationFilter.apply(new AuthenticationFilter.Config());
        Mono<Void> result = filter.filter(exchange, filterChain);
        
        // Then
        StepVerifier.create(result)
            .verifyComplete();
            
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
    
    @Test
    void testAuthenticationFilter_OpenPath_ShouldSkipAuthentication() {
        // Given
        MockServerHttpRequest request = MockServerHttpRequest
            .get("/api/v1/auth/login")
            .build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);
        
        // When
        GatewayFilter filter = authenticationFilter.apply(new AuthenticationFilter.Config());
        Mono<Void> result = filter.filter(exchange, filterChain);
        
        // Then
        StepVerifier.create(result)
            .verifyComplete();
            
        // Should not have authentication headers
        assertThat(exchange.getRequest().getHeaders().getFirst("X-User-ID")).isNull();
    }
    
    @Test
    void testSecurityHeadersFilter_ShouldAddSecurityHeaders() {
        // Given
        MockServerHttpRequest request = MockServerHttpRequest
            .get("/api/v1/test")
            .build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);
        
        // When
        GatewayFilter filter = securityHeadersFilter.apply(new SecurityHeadersFilter.Config());
        Mono<Void> result = filter.filter(exchange, filterChain);
        
        // Then
        StepVerifier.create(result)
            .verifyComplete();
            
        HttpHeaders responseHeaders = exchange.getResponse().getHeaders();
        assertThat(responseHeaders.getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(responseHeaders.getFirst("X-Frame-Options")).isEqualTo("DENY");
        assertThat(responseHeaders.getFirst("X-XSS-Protection")).isEqualTo("1; mode=block");
        assertThat(responseHeaders.getFirst("Referrer-Policy")).isEqualTo("strict-origin-when-cross-origin");
        assertThat(responseHeaders.getFirst("Content-Security-Policy")).isNotNull();
        assertThat(responseHeaders.getFirst("X-Request-ID")).isNotNull();
    }
    
    @Test
    void testRequestValidationFilter_MaliciousXSSContent_ShouldRejectRequest() {
        // Given
        MockServerHttpRequest request = MockServerHttpRequest
            .get("/api/v1/search?q=<script>alert('xss')</script>")
            .build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);
        
        // When
        GatewayFilter filter = requestValidationFilter.apply(new RequestValidationFilter.Config());
        Mono<Void> result = filter.filter(exchange, filterChain);
        
        // Then
        StepVerifier.create(result)
            .verifyComplete();
            
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
    
    @Test
    void testRequestValidationFilter_SQLInjectionContent_ShouldRejectRequest() {
        // Given
        MockServerHttpRequest request = MockServerHttpRequest
            .get("/api/v1/users?id=1 OR 1=1")
            .build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);
        
        // When
        GatewayFilter filter = requestValidationFilter.apply(new RequestValidationFilter.Config());
        Mono<Void> result = filter.filter(exchange, filterChain);
        
        // Then
        StepVerifier.create(result)
            .verifyComplete();
            
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
    
    @Test
    void testRequestValidationFilter_SuspiciousUserAgent_ShouldRejectRequest() {
        // Given
        MockServerHttpRequest request = MockServerHttpRequest
            .get("/api/v1/test")
            .header("User-Agent", "sqlmap/1.0")
            .build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);
        
        // When
        GatewayFilter filter = requestValidationFilter.apply(new RequestValidationFilter.Config());
        Mono<Void> result = filter.filter(exchange, filterChain);
        
        // Then
        StepVerifier.create(result)
            .verifyComplete();
            
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
    
    @Test
    void testRequestValidationFilter_ValidRequest_ShouldAllowRequest() {
        // Given
        MockServerHttpRequest request = MockServerHttpRequest
            .get("/api/v1/test")
            .header("User-Agent", "Mozilla/5.0 (compatible browser)")
            .build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);
        
        // When
        GatewayFilter filter = requestValidationFilter.apply(new RequestValidationFilter.Config());
        Mono<Void> result = filter.filter(exchange, filterChain);
        
        // Then
        StepVerifier.create(result)
            .verifyComplete();
            
        assertThat(exchange.getResponse().getStatusCode()).isNull(); // No error status set
    }
    
    @Test
    void testRequestValidationFilter_UnsupportedHttpMethod_ShouldRejectRequest() {
        // Given
        MockServerHttpRequest request = MockServerHttpRequest
            .method(HttpMethod.TRACE, URI.create("/api/v1/test"))
            .build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);
        
        // When
        GatewayFilter filter = requestValidationFilter.apply(new RequestValidationFilter.Config());
        Mono<Void> result = filter.filter(exchange, filterChain);
        
        // Then
        StepVerifier.create(result)
            .verifyComplete();
            
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
    
    @Test
    void testRequestValidationFilter_LargeRequest_ShouldRejectRequest() {
        // Given
        MockServerHttpRequest request = MockServerHttpRequest
            .post("/api/v1/upload")
            .header("Content-Length", "50000000") // 50MB - exceeds 10MB limit
            .build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);
        
        // When
        GatewayFilter filter = requestValidationFilter.apply(new RequestValidationFilter.Config());
        Mono<Void> result = filter.filter(exchange, filterChain);
        
        // Then
        StepVerifier.create(result)
            .verifyComplete();
            
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
    
    @Test
    void testCombinedFilters_AuthenticatedRequestWithSecurityHeaders() {
        // Given
        String validToken = "valid.jwt.token";
        MockServerHttpRequest request = MockServerHttpRequest
            .get("/api/v1/protected")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken)
            .build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);
        
        when(jwtTokenProvider.validateToken(validToken)).thenReturn(true);
        when(jwtTokenProvider.getUserIdFromToken(validToken)).thenReturn("user123");
        when(jwtTokenProvider.getOrganizationIdFromToken(validToken)).thenReturn("org456");
        when(jwtTokenProvider.getRolesFromToken(validToken)).thenReturn(List.of("USER"));
        
        // When - Apply filters in sequence (as they would be in the gateway)
        GatewayFilter validationFilter = requestValidationFilter.apply(new RequestValidationFilter.Config());
        GatewayFilter authFilter = authenticationFilter.apply(new AuthenticationFilter.Config());
        GatewayFilter securityFilter = securityHeadersFilter.apply(new SecurityHeadersFilter.Config());
        
        Mono<Void> result = validationFilter.filter(exchange, 
            exchange2 -> authFilter.filter(exchange2, 
                exchange3 -> securityFilter.filter(exchange3, filterChain)));
        
        // Then
        StepVerifier.create(result)
            .verifyComplete();
            
        // Should have authentication context
        assertThat(exchange.getRequest().getHeaders().getFirst("X-User-ID")).isEqualTo("user123");
        
        // Should have security headers
        HttpHeaders responseHeaders = exchange.getResponse().getHeaders();
        assertThat(responseHeaders.getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(responseHeaders.getFirst("X-Request-ID")).isNotNull();
    }
}
