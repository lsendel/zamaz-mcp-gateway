package com.zamaz.mcp.gateway.config;

import com.zamaz.mcp.gateway.filter.CircuitBreakerFilter;
import com.zamaz.mcp.gateway.filter.DDoSProtectionFilter;
import com.zamaz.mcp.gateway.filter.RateLimitingFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/**
 * Configuration for security filters in the gateway.
 * Ensures proper ordering and registration of all security filters.
 */
@Configuration
@RequiredArgsConstructor
public class SecurityFilterConfig {

    @Bean
    public FilterRegistrationBean<RateLimitingFilter> rateLimitingFilterRegistration(
            RateLimitingFilter rateLimitingFilter) {
        
        FilterRegistrationBean<RateLimitingFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(rateLimitingFilter);
        registration.addUrlPatterns("/api/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        registration.setName("rateLimitingFilter");
        return registration;
    }

    @Bean
    public FilterRegistrationBean<DDoSProtectionFilter> ddosProtectionFilterRegistration(
            DDoSProtectionFilter ddosProtectionFilter) {
        
        FilterRegistrationBean<DDoSProtectionFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(ddosProtectionFilter);
        registration.addUrlPatterns("/api/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 1);
        registration.setName("ddosProtectionFilter");
        return registration;
    }

    @Bean
    public FilterRegistrationBean<CircuitBreakerFilter> circuitBreakerFilterRegistration(
            CircuitBreakerFilter circuitBreakerFilter) {
        
        FilterRegistrationBean<CircuitBreakerFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(circuitBreakerFilter);
        registration.addUrlPatterns("/api/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 2);
        registration.setName("circuitBreakerFilter");
        return registration;
    }
}