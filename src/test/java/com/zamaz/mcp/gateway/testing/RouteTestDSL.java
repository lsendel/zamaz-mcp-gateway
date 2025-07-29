package com.zamaz.mcp.gateway.testing;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.BodyInserters;

import java.time.Duration;
import java.util.*;
import java.util.function.Consumer;

/**
 * Domain-Specific Language for testing API gateway routes.
 * Provides fluent API for declarative route testing.
 */
public class RouteTestDSL {

    private final WebTestClient webTestClient;
    private final List<RouteTest> routeTests = new ArrayList<>();
    private final Map<String, String> globalHeaders = new HashMap<>();
    
    public RouteTestDSL(WebTestClient webTestClient) {
        this.webTestClient = webTestClient;
        setupDefaultHeaders();
    }

    /**
     * Creates a new route test.
     */
    public static RouteTestBuilder route(String path) {
        return new RouteTestBuilder(path);
    }

    /**
     * Sets global headers for all requests.
     */
    public RouteTestDSL withGlobalHeader(String name, String value) {
        globalHeaders.put(name, value);
        return this;
    }

    /**
     * Sets authentication token for all requests.
     */
    public RouteTestDSL withAuthentication(String token) {
        return withGlobalHeader("Authorization", "Bearer " + token);
    }

    /**
     * Sets organization context for all requests.
     */
    public RouteTestDSL withOrganization(String organizationId) {
        return withGlobalHeader("X-Organization-Id", organizationId);
    }

    /**
     * Executes all configured route tests.
     */
    public RouteTestResults executeAll() {
        RouteTestResults results = new RouteTestResults();
        
        for (RouteTest test : routeTests) {
            try {
                RouteTestResult result = executeTest(test);
                results.addResult(result);
            } catch (Exception e) {
                results.addError(test.getName(), e);
            }
        }
        
        return results;
    }

    /**
     * Executes a specific route test.
     */
    public RouteTestResult execute(RouteTest test) {
        return executeTest(test);
    }

    // Builder class for route tests

    public static class RouteTestBuilder {
        private final String path;
        private HttpMethod method = HttpMethod.GET;
        private final Map<String, String> headers = new HashMap<>();
        private final Map<String, String> queryParams = new HashMap<>();
        private Object requestBody;
        private HttpStatus expectedStatus = HttpStatus.OK;
        private final List<ResponseValidation> validations = new ArrayList<>();
        private Duration timeout = Duration.ofSeconds(5);
        private String name;

        public RouteTestBuilder(String path) {
            this.path = path;
            this.name = "Test " + path;
        }

        public RouteTestBuilder named(String name) {
            this.name = name;
            return this;
        }

        public RouteTestBuilder get() {
            this.method = HttpMethod.GET;
            return this;
        }

        public RouteTestBuilder post() {
            this.method = HttpMethod.POST;
            return this;
        }

        public RouteTestBuilder put() {
            this.method = HttpMethod.PUT;
            return this;
        }

        public RouteTestBuilder delete() {
            this.method = HttpMethod.DELETE;
            return this;
        }

        public RouteTestBuilder patch() {
            this.method = HttpMethod.PATCH;
            return this;
        }

        public RouteTestBuilder withHeader(String name, String value) {
            headers.put(name, value);
            return this;
        }

        public RouteTestBuilder withAuth(String token) {
            return withHeader("Authorization", "Bearer " + token);
        }

        public RouteTestBuilder withOrganization(String orgId) {
            return withHeader("X-Organization-Id", orgId);
        }

        public RouteTestBuilder withContentType(String contentType) {
            return withHeader("Content-Type", contentType);
        }

        public RouteTestBuilder withJsonContent() {
            return withContentType("application/json");
        }

        public RouteTestBuilder withQueryParam(String name, String value) {
            queryParams.put(name, value);
            return this;
        }

        public RouteTestBuilder withBody(Object body) {
            this.requestBody = body;
            return this;
        }

        public RouteTestBuilder expectStatus(HttpStatus status) {
            this.expectedStatus = status;
            return this;
        }

        public RouteTestBuilder expectOk() {
            return expectStatus(HttpStatus.OK);
        }

        public RouteTestBuilder expectCreated() {
            return expectStatus(HttpStatus.CREATED);
        }

        public RouteTestBuilder expectNotFound() {
            return expectStatus(HttpStatus.NOT_FOUND);
        }

        public RouteTestBuilder expectUnauthorized() {
            return expectStatus(HttpStatus.UNAUTHORIZED);
        }

        public RouteTestBuilder expectForbidden() {
            return expectStatus(HttpStatus.FORBIDDEN);
        }

        public RouteTestBuilder expectBadRequest() {
            return expectStatus(HttpStatus.BAD_REQUEST);
        }

        public RouteTestBuilder expectHeader(String name, String value) {
            validations.add(new HeaderValidation(name, value));
            return this;
        }

        public RouteTestBuilder expectJsonPath(String path, Object value) {
            validations.add(new JsonPathValidation(path, value));
            return this;
        }

        public RouteTestBuilder expectBodyContains(String text) {
            validations.add(new BodyContainsValidation(text));
            return this;
        }

        public RouteTestBuilder expectBodyMatches(String regex) {
            validations.add(new BodyMatchesValidation(regex));
            return this;
        }

        public RouteTestBuilder expectResponseTime(Duration maxTime) {
            validations.add(new ResponseTimeValidation(maxTime));
            return this;
        }

        public RouteTestBuilder withTimeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        public RouteTest build() {
            return new RouteTest(name, path, method, headers, queryParams, 
                               requestBody, expectedStatus, validations, timeout);
        }
    }

    // Route test configuration class

    public static class RouteTest {
        private final String name;
        private final String path;
        private final HttpMethod method;
        private final Map<String, String> headers;
        private final Map<String, String> queryParams;
        private final Object requestBody;
        private final HttpStatus expectedStatus;
        private final List<ResponseValidation> validations;
        private final Duration timeout;

        public RouteTest(String name, String path, HttpMethod method, 
                        Map<String, String> headers, Map<String, String> queryParams,
                        Object requestBody, HttpStatus expectedStatus, 
                        List<ResponseValidation> validations, Duration timeout) {
            this.name = name;
            this.path = path;
            this.method = method;
            this.headers = new HashMap<>(headers);
            this.queryParams = new HashMap<>(queryParams);
            this.requestBody = requestBody;
            this.expectedStatus = expectedStatus;
            this.validations = new ArrayList<>(validations);
            this.timeout = timeout;
        }

        // Getters
        public String getName() { return name; }
        public String getPath() { return path; }
        public HttpMethod getMethod() { return method; }
        public Map<String, String> getHeaders() { return headers; }
        public Map<String, String> getQueryParams() { return queryParams; }
        public Object getRequestBody() { return requestBody; }
        public HttpStatus getExpectedStatus() { return expectedStatus; }
        public List<ResponseValidation> getValidations() { return validations; }
        public Duration getTimeout() { return timeout; }
    }

    // Response validation interfaces and implementations

    public interface ResponseValidation {
        void validate(WebTestClient.ResponseSpec response) throws Exception;
        String getDescription();
    }

    public static class HeaderValidation implements ResponseValidation {
        private final String headerName;
        private final String expectedValue;

        public HeaderValidation(String headerName, String expectedValue) {
            this.headerName = headerName;
            this.expectedValue = expectedValue;
        }

        @Override
        public void validate(WebTestClient.ResponseSpec response) throws Exception {
            response.expectHeader().valueEquals(headerName, expectedValue);
        }

        @Override
        public String getDescription() {
            return String.format("Header %s should equal %s", headerName, expectedValue);
        }
    }

    public static class JsonPathValidation implements ResponseValidation {
        private final String jsonPath;
        private final Object expectedValue;

        public JsonPathValidation(String jsonPath, Object expectedValue) {
            this.jsonPath = jsonPath;
            this.expectedValue = expectedValue;
        }

        @Override
        public void validate(WebTestClient.ResponseSpec response) throws Exception {
            response.expectBody().jsonPath(jsonPath).isEqualTo(expectedValue);
        }

        @Override
        public String getDescription() {
            return String.format("JSON path %s should equal %s", jsonPath, expectedValue);
        }
    }

    public static class BodyContainsValidation implements ResponseValidation {
        private final String expectedText;

        public BodyContainsValidation(String expectedText) {
            this.expectedText = expectedText;
        }

        @Override
        public void validate(WebTestClient.ResponseSpec response) throws Exception {
            response.expectBody(String.class).value(body -> {
                if (!body.contains(expectedText)) {
                    throw new AssertionError("Response body does not contain: " + expectedText);
                }
            });
        }

        @Override
        public String getDescription() {
            return String.format("Response body should contain '%s'", expectedText);
        }
    }

    public static class BodyMatchesValidation implements ResponseValidation {
        private final String regex;

        public BodyMatchesValidation(String regex) {
            this.regex = regex;
        }

        @Override
        public void validate(WebTestClient.ResponseSpec response) throws Exception {
            response.expectBody(String.class).value(body -> {
                if (!body.matches(regex)) {
                    throw new AssertionError("Response body does not match regex: " + regex);
                }
            });
        }

        @Override
        public String getDescription() {
            return String.format("Response body should match regex '%s'", regex);
        }
    }

    public static class ResponseTimeValidation implements ResponseValidation {
        private final Duration maxTime;
        private long startTime;

        public ResponseTimeValidation(Duration maxTime) {
            this.maxTime = maxTime;
        }

        @Override
        public void validate(WebTestClient.ResponseSpec response) throws Exception {
            // Note: This is a simplified implementation
            // In a real scenario, you'd need to measure the actual response time
            long duration = System.currentTimeMillis() - startTime;
            if (duration > maxTime.toMillis()) {
                throw new AssertionError(String.format(
                    "Response time %dms exceeds maximum %dms", duration, maxTime.toMillis()));
            }
        }

        @Override
        public String getDescription() {
            return String.format("Response time should be less than %dms", maxTime.toMillis());
        }

        public void markStart() {
            this.startTime = System.currentTimeMillis();
        }
    }

    // Test execution and results

    private RouteTestResult executeTest(RouteTest test) {
        long startTime = System.currentTimeMillis();
        RouteTestResult result = new RouteTestResult(test.getName());
        
        try {
            // Build the request
            WebTestClient.RequestHeadersSpec<?> request = buildRequest(test);
            
            // Mark start time for response time validations
            test.getValidations().stream()
                .filter(v -> v instanceof ResponseTimeValidation)
                .map(v -> (ResponseTimeValidation) v)
                .forEach(ResponseTimeValidation::markStart);
            
            // Execute the request
            WebTestClient.ResponseSpec response = request.exchange();
            
            // Validate status
            response.expectStatus().isEqualTo(test.getExpectedStatus());
            
            // Execute custom validations
            for (ResponseValidation validation : test.getValidations()) {
                try {
                    validation.validate(response);
                    result.addValidationResult(validation.getDescription(), true, null);
                } catch (Exception e) {
                    result.addValidationResult(validation.getDescription(), false, e);
                }
            }
            
            long endTime = System.currentTimeMillis();
            result.setResponseTimeMs(endTime - startTime);
            result.setSuccess(true);
            
        } catch (Exception e) {
            long endTime = System.currentTimeMillis();
            result.setResponseTimeMs(endTime - startTime);
            result.setSuccess(false);
            result.setError(e);
        }
        
        return result;
    }

    private WebTestClient.RequestHeadersSpec<?> buildRequest(RouteTest test) {
        // Start building the request
        WebTestClient.RequestBodySpec request = webTestClient
            .method(test.getMethod())
            .uri(uriBuilder -> {
                uriBuilder.path(test.getPath());
                test.getQueryParams().forEach(uriBuilder::queryParam);
                return uriBuilder.build();
            });

        // Add global headers
        globalHeaders.forEach(request::header);
        
        // Add test-specific headers
        test.getHeaders().forEach(request::header);

        // Add body if present
        if (test.getRequestBody() != null) {
            return request.body(BodyInserters.fromValue(test.getRequestBody()));
        } else {
            return request;
        }
    }

    private void setupDefaultHeaders() {
        globalHeaders.put("User-Agent", "RouteTestDSL/1.0");
        globalHeaders.put("Accept", "application/json");
    }

    // Fluent API entry points

    public RouteTestDSL addTest(RouteTest test) {
        routeTests.add(test);
        return this;
    }

    public RouteTestDSL addTest(Consumer<RouteTestBuilder> testConfiguration) {
        RouteTestBuilder builder = new RouteTestBuilder("/");
        testConfiguration.accept(builder);
        routeTests.add(builder.build());
        return this;
    }

    // Common route test patterns

    public RouteTestDSL testHealthEndpoint() {
        return addTest(route("/health")
            .get()
            .expectOk()
            .expectJsonPath("$.status", "UP")
            .build());
    }

    public RouteTestDSL testAuthenticatedEndpoint(String path, String token) {
        return addTest(route(path)
            .get()
            .withAuth(token)
            .expectOk()
            .build());
    }

    public RouteTestDSL testUnauthorizedAccess(String path) {
        return addTest(route(path)
            .get()
            .expectUnauthorized()
            .build());
    }

    public RouteTestDSL testCrudOperations(String basePath, Object createData, Object updateData, String token) {
        // Create
        addTest(route(basePath)
            .post()
            .withAuth(token)
            .withJsonContent()
            .withBody(createData)
            .expectCreated()
            .build());

        // Read
        addTest(route(basePath + "/1")
            .get()
            .withAuth(token)
            .expectOk()
            .build());

        // Update
        addTest(route(basePath + "/1")
            .put()
            .withAuth(token)
            .withJsonContent()
            .withBody(updateData)
            .expectOk()
            .build());

        // Delete
        addTest(route(basePath + "/1")
            .delete()
            .withAuth(token)
            .expectOk()
            .build());

        return this;
    }

    // Result classes

    public static class RouteTestResult {
        private final String testName;
        private boolean success;
        private Exception error;
        private long responseTimeMs;
        private final List<ValidationResult> validationResults = new ArrayList<>();

        public RouteTestResult(String testName) {
            this.testName = testName;
        }

        public void addValidationResult(String validation, boolean passed, Exception error) {
            validationResults.add(new ValidationResult(validation, passed, error));
        }

        // Getters and setters
        public String getTestName() { return testName; }
        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }
        public Exception getError() { return error; }
        public void setError(Exception error) { this.error = error; }
        public long getResponseTimeMs() { return responseTimeMs; }
        public void setResponseTimeMs(long responseTimeMs) { this.responseTimeMs = responseTimeMs; }
        public List<ValidationResult> getValidationResults() { return validationResults; }

        public boolean allValidationsPassed() {
            return validationResults.stream().allMatch(v -> v.passed);
        }

        public static class ValidationResult {
            public final String validation;
            public final boolean passed;
            public final Exception error;

            public ValidationResult(String validation, boolean passed, Exception error) {
                this.validation = validation;
                this.passed = passed;
                this.error = error;
            }
        }
    }

    public static class RouteTestResults {
        private final List<RouteTestResult> results = new ArrayList<>();
        private final Map<String, Exception> errors = new HashMap<>();

        public void addResult(RouteTestResult result) {
            results.add(result);
        }

        public void addError(String testName, Exception error) {
            errors.put(testName, error);
        }

        public List<RouteTestResult> getResults() { return results; }
        public Map<String, Exception> getErrors() { return errors; }

        public boolean allTestsPassed() {
            return errors.isEmpty() && 
                   results.stream().allMatch(r -> r.isSuccess() && r.allValidationsPassed());
        }

        public int getPassedCount() {
            return (int) results.stream().filter(r -> r.isSuccess() && r.allValidationsPassed()).count();
        }

        public int getFailedCount() {
            return results.size() + errors.size() - getPassedCount();
        }

        public double getAverageResponseTime() {
            return results.stream()
                .mapToLong(RouteTestResult::getResponseTimeMs)
                .average()
                .orElse(0.0);
        }
    }
}