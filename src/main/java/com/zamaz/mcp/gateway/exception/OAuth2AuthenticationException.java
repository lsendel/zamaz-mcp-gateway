package com.zamaz.mcp.gateway.exception;

/**
 * Exception thrown when OAuth2 authentication fails.
 */
public class OAuth2AuthenticationException extends RuntimeException {

    public OAuth2AuthenticationException(String message) {
        super(message);
    }

    public OAuth2AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}