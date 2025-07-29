package com.zamaz.mcp.gateway.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Fallback controller for circuit breaker
 */
@RestController
@RequestMapping("/fallback")
public class FallbackController {
    
    @RequestMapping("/organization")
    public Mono<ResponseEntity<Map<String, Object>>> organizationFallback() {
        return createFallbackResponse("Organization service is temporarily unavailable");
    }
    
    @RequestMapping("/llm")
    public Mono<ResponseEntity<Map<String, Object>>> llmFallback() {
        return createFallbackResponse("LLM service is temporarily unavailable");
    }
    
    @RequestMapping("/controller")
    public Mono<ResponseEntity<Map<String, Object>>> controllerFallback() {
        return createFallbackResponse("Debate controller service is temporarily unavailable");
    }
    
    @RequestMapping("/rag")
    public Mono<ResponseEntity<Map<String, Object>>> ragFallback() {
        return createFallbackResponse("RAG service is temporarily unavailable");
    }
    
    @RequestMapping("/template")
    public Mono<ResponseEntity<Map<String, Object>>> templateFallback() {
        return createFallbackResponse("Template service is temporarily unavailable");
    }
    
    private Mono<ResponseEntity<Map<String, Object>>> createFallbackResponse(String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("error", "Service Unavailable");
        response.put("message", message);
        response.put("timestamp", Instant.now().toString());
        response.put("status", HttpStatus.SERVICE_UNAVAILABLE.value());
        
        return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response));
    }
}