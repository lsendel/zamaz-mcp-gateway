package com.zamaz.mcp.gateway.testing;

import org.springframework.web.reactive.socket.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;

import java.net.URI;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * WebSocket test client for testing real-time communication.
 * Supports full duplex testing, connection management, and message validation.
 */
public class WebSocketTestClient {

    private final WebSocketClient webSocketClient;
    private final List<WebSocketConnection> connections = new CopyOnWriteArrayList<>();
    private final Map<String, MessageHandler> messageHandlers = new ConcurrentHashMap<>();
    private final Map<String, ConnectionHandler> connectionHandlers = new ConcurrentHashMap<>();
    
    public WebSocketTestClient(WebSocketClient webSocketClient) {
        this.webSocketClient = webSocketClient;
    }

    /**
     * Creates a new WebSocket connection for testing.
     */
    public WebSocketConnectionBuilder connect(String uri) {
        return new WebSocketConnectionBuilder(URI.create(uri));
    }

    /**
     * Creates a new WebSocket connection with authentication.
     */
    public WebSocketConnectionBuilder connectWithAuth(String uri, String token) {
        return new WebSocketConnectionBuilder(URI.create(uri))
            .withHeader("Authorization", "Bearer " + token);
    }

    /**
     * Creates a new WebSocket connection with organization context.
     */
    public WebSocketConnectionBuilder connectWithOrganization(String uri, String orgId) {
        return new WebSocketConnectionBuilder(URI.create(uri))
            .withHeader("X-Organization-Id", orgId);
    }

    /**
     * Builder for WebSocket connections.
     */
    public class WebSocketConnectionBuilder {
        private final URI uri;
        private final Map<String, String> headers = new HashMap<>();
        private Duration connectTimeout = Duration.ofSeconds(5);
        private String connectionId;

        public WebSocketConnectionBuilder(URI uri) {
            this.uri = uri;
            this.connectionId = "conn-" + UUID.randomUUID().toString().substring(0, 8);
        }

        public WebSocketConnectionBuilder withId(String connectionId) {
            this.connectionId = connectionId;
            return this;
        }

        public WebSocketConnectionBuilder withHeader(String name, String value) {
            headers.put(name, value);
            return this;
        }

        public WebSocketConnectionBuilder withConnectTimeout(Duration timeout) {
            this.connectTimeout = timeout;
            return this;
        }

        public WebSocketConnection build() {
            WebSocketConnection connection = new WebSocketConnection(connectionId, uri, headers);
            connections.add(connection);
            return connection;
        }

        public Mono<WebSocketConnection> execute() {
            WebSocketConnection connection = build();
            return connection.connect(connectTimeout);
        }
    }

    /**
     * Represents a WebSocket connection for testing.
     */
    public class WebSocketConnection {
        private final String connectionId;
        private final URI uri;
        private final Map<String, String> headers;
        private final List<String> sentMessages = new CopyOnWriteArrayList<>();
        private final List<String> receivedMessages = new CopyOnWriteArrayList<>();
        private final AtomicBoolean connected = new AtomicBoolean(false);
        private final AtomicReference<WebSocketSession> session = new AtomicReference<>();
        private final Sinks.Many<String> outgoingSink = Sinks.many().multicast().onBackpressureBuffer();
        private final List<MessageExpectation> expectations = new CopyOnWriteArrayList<>();
        private final List<Consumer<String>> messageListeners = new CopyOnWriteArrayList<>();
        private final List<Consumer<WebSocketConnection>> connectionListeners = new CopyOnWriteArrayList<>();
        private final List<Consumer<Throwable>> errorListeners = new CopyOnWriteArrayList<>();

        public WebSocketConnection(String connectionId, URI uri, Map<String, String> headers) {
            this.connectionId = connectionId;
            this.uri = uri;
            this.headers = new HashMap<>(headers);
        }

        public Mono<WebSocketConnection> connect(Duration timeout) {
            return webSocketClient
                .execute(uri, createWebSocketHandler())
                .timeout(timeout)
                .then(Mono.fromCallable(() -> {
                    connected.set(true);
                    connectionListeners.forEach(listener -> listener.accept(this));
                    return this;
                }))
                .onErrorResume(throwable -> {
                    errorListeners.forEach(listener -> listener.accept(throwable));
                    return Mono.error(throwable);
                });
        }

        public void send(String message) {
            if (!connected.get()) {
                throw new IllegalStateException("Connection not established");
            }
            
            sentMessages.add(message);
            outgoingSink.tryEmitNext(message);
        }

        public void sendJson(Object object) {
            // In a real implementation, you'd use a JSON serializer
            send(object.toString());
        }

        public void disconnect() {
            if (session.get() != null) {
                session.get().close().subscribe();
            }
            connected.set(false);
            outgoingSink.tryEmitComplete();
        }

        public MessageExpectationBuilder expectMessage() {
            return new MessageExpectationBuilder(this);
        }

        public WebSocketConnection onMessage(Consumer<String> listener) {
            messageListeners.add(listener);
            return this;
        }

        public WebSocketConnection onConnect(Consumer<WebSocketConnection> listener) {
            connectionListeners.add(listener);
            return this;
        }

        public WebSocketConnection onError(Consumer<Throwable> listener) {
            errorListeners.add(listener);
            return this;
        }

        public boolean waitForConnection(Duration timeout) {
            try {
                long timeoutMs = timeout.toMillis();
                long start = System.currentTimeMillis();
                
                while (!connected.get() && (System.currentTimeMillis() - start) < timeoutMs) {
                    Thread.sleep(10);
                }
                
                return connected.get();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }

        public boolean waitForMessage(Predicate<String> matcher, Duration timeout) {
            try {
                long timeoutMs = timeout.toMillis();
                long start = System.currentTimeMillis();
                
                while ((System.currentTimeMillis() - start) < timeoutMs) {
                    if (receivedMessages.stream().anyMatch(matcher)) {
                        return true;
                    }
                    Thread.sleep(10);
                }
                
                return false;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }

        public boolean waitForMessageCount(int expectedCount, Duration timeout) {
            try {
                long timeoutMs = timeout.toMillis();
                long start = System.currentTimeMillis();
                
                while (receivedMessages.size() < expectedCount && 
                       (System.currentTimeMillis() - start) < timeoutMs) {
                    Thread.sleep(10);
                }
                
                return receivedMessages.size() >= expectedCount;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }

        private WebSocketHandler createWebSocketHandler() {
            return session -> {
                this.session.set(session);
                
                Mono<Void> input = session.receive()
                    .map(WebSocketMessage::getPayloadAsText)
                    .doOnNext(message -> {
                        receivedMessages.add(message);
                        messageListeners.forEach(listener -> listener.accept(message));
                        processExpectations(message);
                    })
                    .then();

                Mono<Void> output = session.send(
                    outgoingSink.asFlux()
                        .map(session::textMessage)
                );

                return Mono.zip(input, output).then();
            };
        }

        private void processExpectations(String message) {
            expectations.removeIf(expectation -> {
                if (expectation.matches(message)) {
                    expectation.markMet();
                    return true;
                }
                return false;
            });
        }

        // Getters
        public String getConnectionId() { return connectionId; }
        public URI getUri() { return uri; }
        public boolean isConnected() { return connected.get(); }
        public List<String> getSentMessages() { return new ArrayList<>(sentMessages); }
        public List<String> getReceivedMessages() { return new ArrayList<>(receivedMessages); }
        public int getSentMessageCount() { return sentMessages.size(); }
        public int getReceivedMessageCount() { return receivedMessages.size(); }
    }

    /**
     * Builder for message expectations.
     */
    public static class MessageExpectationBuilder {
        private final WebSocketConnection connection;
        private Predicate<String> matcher;
        private Duration timeout = Duration.ofSeconds(5);
        private String description = "Message expectation";

        public MessageExpectationBuilder(WebSocketConnection connection) {
            this.connection = connection;
        }

        public MessageExpectationBuilder containing(String text) {
            this.matcher = message -> message.contains(text);
            this.description = "Message containing '" + text + "'";
            return this;
        }

        public MessageExpectationBuilder matching(String regex) {
            this.matcher = message -> message.matches(regex);
            this.description = "Message matching regex '" + regex + "'";
            return this;
        }

        public MessageExpectationBuilder equalTo(String expected) {
            this.matcher = message -> message.equals(expected);
            this.description = "Message equal to '" + expected + "'";
            return this;
        }

        public MessageExpectationBuilder satisfying(Predicate<String> predicate) {
            this.matcher = predicate;
            this.description = "Message satisfying predicate";
            return this;
        }

        public MessageExpectationBuilder withTimeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        public MessageExpectationBuilder describedAs(String description) {
            this.description = description;
            return this;
        }

        public MessageExpectation build() {
            MessageExpectation expectation = new MessageExpectation(matcher, timeout, description);
            connection.expectations.add(expectation);
            return expectation;
        }

        public boolean await() {
            MessageExpectation expectation = build();
            return expectation.await();
        }
    }

    /**
     * Represents an expectation for a WebSocket message.
     */
    public static class MessageExpectation {
        private final Predicate<String> matcher;
        private final Duration timeout;
        private final String description;
        private final CountDownLatch latch = new CountDownLatch(1);
        private final AtomicBoolean met = new AtomicBoolean(false);

        public MessageExpectation(Predicate<String> matcher, Duration timeout, String description) {
            this.matcher = matcher;
            this.timeout = timeout;
            this.description = description;
        }

        public boolean matches(String message) {
            return matcher.test(message);
        }

        public void markMet() {
            met.set(true);
            latch.countDown();
        }

        public boolean await() {
            try {
                return latch.await(timeout.toMillis(), TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }

        public boolean isMet() {
            return met.get();
        }

        public String getDescription() {
            return description;
        }
    }

    /**
     * Tests multiple WebSocket connections concurrently.
     */
    public ConcurrentWebSocketTest testConcurrentConnections() {
        return new ConcurrentWebSocketTest(this);
    }

    /**
     * Tests WebSocket communication patterns.
     */
    public static class ConcurrentWebSocketTest {
        private final WebSocketTestClient client;
        private final List<WebSocketConnection> testConnections = new ArrayList<>();
        private final Map<String, List<String>> connectionMessages = new HashMap<>();

        public ConcurrentWebSocketTest(WebSocketTestClient client) {
            this.client = client;
        }

        public ConcurrentWebSocketTest addConnection(String uri, String connectionId) {
            WebSocketConnection connection = client.connect(uri)
                .withId(connectionId)
                .build();
            testConnections.add(connection);
            connectionMessages.put(connectionId, new ArrayList<>());
            return this;
        }

        public ConcurrentWebSocketTest addAuthenticatedConnection(String uri, String token, String connectionId) {
            WebSocketConnection connection = client.connectWithAuth(uri, token)
                .withId(connectionId)
                .build();
            testConnections.add(connection);
            connectionMessages.put(connectionId, new ArrayList<>());
            return this;
        }

        public ConcurrentTestResult execute() {
            ConcurrentTestResult result = new ConcurrentTestResult();
            
            // Connect all connections
            List<Mono<WebSocketConnection>> connectMonos = testConnections.stream()
                .map(conn -> conn.connect(Duration.ofSeconds(5)))
                .toList();
            
            try {
                // Wait for all connections
                List<WebSocketConnection> connected = Flux.fromIterable(connectMonos)
                    .flatMap(mono -> mono)
                    .collectList()
                    .block(Duration.ofSeconds(10));
                
                if (connected == null || connected.size() != testConnections.size()) {
                    result.setSuccess(false);
                    result.setError(new RuntimeException("Failed to establish all connections"));
                    return result;
                }
                
                // Test message broadcasting
                testMessageBroadcasting(connected, result);
                
                // Test isolation
                testConnectionIsolation(connected, result);
                
                result.setSuccess(true);
                
            } catch (Exception e) {
                result.setSuccess(false);
                result.setError(e);
            } finally {
                // Cleanup connections
                testConnections.forEach(WebSocketConnection::disconnect);
            }
            
            return result;
        }

        private void testMessageBroadcasting(List<WebSocketConnection> connections, ConcurrentTestResult result) {
            // Send messages from first connection
            WebSocketConnection sender = connections.get(0);
            String testMessage = "broadcast-test-" + System.currentTimeMillis();
            
            // Set up listeners for other connections
            List<CountDownLatch> latches = new ArrayList<>();
            for (int i = 1; i < connections.size(); i++) {
                CountDownLatch latch = new CountDownLatch(1);
                latches.add(latch);
                WebSocketConnection receiver = connections.get(i);
                receiver.onMessage(message -> {
                    if (message.contains(testMessage)) {
                        latch.countDown();
                    }
                });
            }
            
            // Send the message
            sender.send(testMessage);
            
            // Wait for all receivers to get the message
            boolean allReceived = latches.stream().allMatch(latch -> {
                try {
                    return latch.await(2, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            });
            
            result.setBroadcastSuccess(allReceived);
        }

        private void testConnectionIsolation(List<WebSocketConnection> connections, ConcurrentTestResult result) {
            // Test that connections can send/receive independently
            Map<String, Boolean> isolationResults = new HashMap<>();
            
            for (WebSocketConnection connection : connections) {
                String uniqueMessage = "isolation-" + connection.getConnectionId();
                connection.send(uniqueMessage);
                
                // Verify the connection received its own message (if echo is enabled)
                boolean isolated = connection.waitForMessage(
                    msg -> msg.contains(uniqueMessage), 
                    Duration.ofSeconds(2)
                );
                
                isolationResults.put(connection.getConnectionId(), isolated);
            }
            
            result.setIsolationResults(isolationResults);
        }
    }

    /**
     * Result of concurrent WebSocket testing.
     */
    public static class ConcurrentTestResult {
        private boolean success;
        private Exception error;
        private boolean broadcastSuccess;
        private Map<String, Boolean> isolationResults = new HashMap<>();

        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }
        public Exception getError() { return error; }
        public void setError(Exception error) { this.error = error; }
        public boolean isBroadcastSuccess() { return broadcastSuccess; }
        public void setBroadcastSuccess(boolean broadcastSuccess) { this.broadcastSuccess = broadcastSuccess; }
        public Map<String, Boolean> getIsolationResults() { return isolationResults; }
        public void setIsolationResults(Map<String, Boolean> isolationResults) { this.isolationResults = isolationResults; }
        
        public boolean allIsolationTestsPassed() {
            return isolationResults.values().stream().allMatch(Boolean::booleanValue);
        }
    }

    // Utility methods

    public void disconnectAll() {
        connections.forEach(WebSocketConnection::disconnect);
        connections.clear();
    }

    public List<WebSocketConnection> getActiveConnections() {
        return connections.stream()
            .filter(WebSocketConnection::isConnected)
            .toList();
    }

    public int getActiveConnectionCount() {
        return getActiveConnections().size();
    }

    // Message and connection handlers

    public interface MessageHandler {
        void handle(String connectionId, String message);
    }

    public interface ConnectionHandler {
        void onConnect(String connectionId);
        void onDisconnect(String connectionId);
        void onError(String connectionId, Throwable error);
    }
}