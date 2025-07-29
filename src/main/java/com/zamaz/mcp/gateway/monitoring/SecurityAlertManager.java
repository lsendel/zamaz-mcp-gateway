package com.zamaz.mcp.gateway.monitoring;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages security alerts and notifications for critical security events.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class SecurityAlertManager {

    private final ApplicationEventPublisher eventPublisher;
    private final JavaMailSender mailSender;
    private final RestTemplate restTemplate = new RestTemplate();
    
    @Value("${security.alerts.webhook.url:#{null}}")
    private String webhookUrl;
    
    @Value("${security.alerts.slack.webhook:#{null}}")
    private String slackWebhook;
    
    @Value("${security.alerts.teams.webhook:#{null}}")
    private String teamsWebhook;
    
    @Value("${security.alerts.email.enabled:false}")
    private boolean emailAlertsEnabled;
    
    @Value("${security.alerts.email.to:admin@mcp-debate.com}")
    private String alertEmailTo;
    
    @Value("${security.alerts.email.from:security@mcp-debate.com}")
    private String alertEmailFrom;
    
    @Value("${security.alerts.enabled:true}")
    private boolean alertsEnabled;
    
    // Alert throttling to prevent spam
    private final ConcurrentHashMap<String, LocalDateTime> lastAlertTimes = new ConcurrentHashMap<>();
    private final int ALERT_THROTTLE_MINUTES = 5;
    
    /**
     * Send critical security alert
     */
    public void sendCriticalAlert(String title, String message, Map<String, String> details) {
        if (!alertsEnabled) {
            return;
        }
        
        SecurityAlert alert = SecurityAlert.builder()
                .severity(AlertSeverity.CRITICAL)
                .title(title)
                .message(message)
                .details(details)
                .timestamp(LocalDateTime.now())
                .build();
                
        processAlert(alert);
    }
    
    /**
     * Send high priority security alert
     */
    public void sendHighAlert(String title, String message, Map<String, String> details) {
        if (!alertsEnabled) {
            return;
        }
        
        SecurityAlert alert = SecurityAlert.builder()
                .severity(AlertSeverity.HIGH)
                .title(title)
                .message(message)
                .details(details)
                .timestamp(LocalDateTime.now())
                .build();
                
        processAlert(alert);
    }
    
    /**
     * Send medium priority security alert
     */
    public void sendMediumAlert(String title, String message, Map<String, String> details) {
        if (!alertsEnabled) {
            return;
        }
        
        SecurityAlert alert = SecurityAlert.builder()
                .severity(AlertSeverity.MEDIUM)
                .title(title)
                .message(message)
                .details(details)
                .timestamp(LocalDateTime.now())
                .build();
                
        processAlert(alert);
    }
    
    /**
     * Send authentication failure alert
     */
    public void alertAuthenticationFailures(String clientIp, int failureCount, String timeWindow) {
        if (isThrottled("auth_failures_" + clientIp)) {
            return;
        }
        
        Map<String, String> details = new HashMap<>();
        details.put("clientIP", clientIp);
        details.put("failureCount", String.valueOf(failureCount));
        details.put("timeWindow", timeWindow);
        details.put("action", "Consider blocking IP or implementing additional verification");
        
        sendHighAlert(
            "🚨 Multiple Authentication Failures Detected",
            String.format("IP %s has %d failed authentication attempts in %s", clientIp, failureCount, timeWindow),
            details
        );
    }
    
    /**
     * Send DDoS attack alert
     */
    public void alertDDoSAttack(String attackType, String clientIp, int requestCount, String timeWindow) {
        if (isThrottled("ddos_" + clientIp)) {
            return;
        }
        
        Map<String, String> details = new HashMap<>();
        details.put("attackType", attackType);
        details.put("clientIP", clientIp);
        details.put("requestCount", String.valueOf(requestCount));
        details.put("timeWindow", timeWindow);
        details.put("action", "IP automatically blocked by DDoS protection");
        
        sendCriticalAlert(
            "🛡️ DDoS Attack Detected and Blocked",
            String.format("%s DDoS attack from %s: %d requests in %s", attackType, clientIp, requestCount, timeWindow),
            details
        );
    }
    
    /**
     * Send suspicious activity alert
     */
    public void alertSuspiciousActivity(String activityType, String clientId, String details) {
        if (isThrottled("suspicious_" + clientId)) {
            return;
        }
        
        Map<String, String> alertDetails = new HashMap<>();
        alertDetails.put("activityType", activityType);
        alertDetails.put("clientId", clientId);
        alertDetails.put("details", details);
        alertDetails.put("action", "Investigate and consider additional monitoring");
        
        sendMediumAlert(
            "🔍 Suspicious Activity Detected",
            String.format("Suspicious %s activity detected from %s", activityType, clientId),
            alertDetails
        );
    }
    
    /**
     * Send circuit breaker alert
     */
    public void alertCircuitBreakerOpen(String serviceName, String reason) {
        if (isThrottled("circuit_" + serviceName)) {
            return;
        }
        
        Map<String, String> details = new HashMap<>();
        details.put("serviceName", serviceName);
        details.put("reason", reason);
        details.put("action", "Check service health and resolve underlying issues");
        
        sendHighAlert(
            "⚡ Circuit Breaker Opened",
            String.format("Circuit breaker opened for service %s: %s", serviceName, reason),
            details
        );
    }
    
    /**
     * Send security configuration alert
     */
    public void alertSecurityMisconfiguration(String component, String issue, String recommendation) {
        Map<String, String> details = new HashMap<>();
        details.put("component", component);
        details.put("issue", issue);
        details.put("recommendation", recommendation);
        
        sendMediumAlert(
            "⚠️ Security Configuration Issue",
            String.format("Security configuration issue in %s: %s", component, issue),
            details
        );
    }
    
    /**
     * Send data breach alert
     */
    public void alertDataBreach(String dataType, String accessedBy, String details) {
        Map<String, String> alertDetails = new HashMap<>();
        alertDetails.put("dataType", dataType);
        alertDetails.put("accessedBy", accessedBy);
        alertDetails.put("details", details);
        alertDetails.put("action", "IMMEDIATE INVESTIGATION REQUIRED");
        
        sendCriticalAlert(
            "🚨 POTENTIAL DATA BREACH DETECTED",
            String.format("Unauthorized access to %s data by %s", dataType, accessedBy),
            alertDetails
        );
    }
    
    /**
     * Process the alert through all configured channels
     */
    private void processAlert(SecurityAlert alert) {
        log.warn("Security Alert [{}]: {} - {}", alert.getSeverity(), alert.getTitle(), alert.getMessage());
        
        // Send to application event system
        eventPublisher.publishEvent(new SecurityAlertEvent(alert));
        
        // Send to external systems based on severity
        switch (alert.getSeverity()) {
            case CRITICAL:
                sendToAllChannels(alert);
                break;
            case HIGH:
                sendToSlack(alert);
                sendToTeams(alert);
                sendToWebhook(alert);
                break;
            case MEDIUM:
                sendToSlack(alert);
                sendToWebhook(alert);
                break;
            case LOW:
                // Only log for low priority
                break;
            case INFO:
                // Only log for info priority
                break;
        }
        
        // Update throttling
        updateAlertThrottle(alert);
    }
    
    /**
     * Send alert to all configured channels
     */
    private void sendToAllChannels(SecurityAlert alert) {
        sendToSlack(alert);
        sendToTeams(alert);
        sendToWebhook(alert);
        if (emailAlertsEnabled) {
            sendEmail(alert);
        }
    }
    
    /**
     * Send alert to Slack
     */
    private void sendToSlack(SecurityAlert alert) {
        if (slackWebhook == null) {
            return;
        }
        
        try {
            Map<String, Object> payload = new HashMap<>();
            payload.put("text", formatSlackMessage(alert));
            payload.put("username", "MCP Security Bot");
            payload.put("icon_emoji", getSeverityEmoji(alert.getSeverity()));
            
            restTemplate.postForEntity(slackWebhook, payload, String.class);
            log.debug("Alert sent to Slack: {}", alert.getTitle());
        } catch (Exception e) {
            log.error("Failed to send alert to Slack", e);
        }
    }
    
    /**
     * Send alert to Microsoft Teams
     */
    private void sendToTeams(SecurityAlert alert) {
        if (teamsWebhook == null) {
            return;
        }
        
        try {
            Map<String, Object> payload = new HashMap<>();
            payload.put("@type", "MessageCard");
            payload.put("@context", "http://schema.org/extensions");
            payload.put("themeColor", getSeverityColor(alert.getSeverity()));
            payload.put("summary", alert.getTitle());
            payload.put("title", alert.getTitle());
            payload.put("text", alert.getMessage());
            
            restTemplate.postForEntity(teamsWebhook, payload, String.class);
            log.debug("Alert sent to Teams: {}", alert.getTitle());
        } catch (Exception e) {
            log.error("Failed to send alert to Teams", e);
        }
    }
    
    /**
     * Send alert to generic webhook
     */
    private void sendToWebhook(SecurityAlert alert) {
        if (webhookUrl == null) {
            return;
        }
        
        try {
            restTemplate.postForEntity(webhookUrl, alert, String.class);
            log.debug("Alert sent to webhook: {}", alert.getTitle());
        } catch (Exception e) {
            log.error("Failed to send alert to webhook", e);
        }
    }
    
    /**
     * Send email alert using Spring Mail
     */
    private void sendEmail(SecurityAlert alert) {
        if (!emailAlertsEnabled) {
            log.debug("Email alerts disabled");
            return;
        }
        
        if (mailSender == null) {
            log.warn("Mail sender not configured. Email alerts cannot be sent.");
            return;
        }
        
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(alertEmailFrom);
            message.setTo(alertEmailTo);
            message.setSubject("[" + alert.getSeverity() + "] " + alert.getTitle());
            
            StringBuilder body = new StringBuilder();
            body.append("Security Alert Details:\n\n");
            body.append("Severity: ").append(alert.getSeverity()).append("\n");
            body.append("Time: ").append(alert.getTimestamp().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)).append("\n");
            body.append("Title: ").append(alert.getTitle()).append("\n");
            body.append("Message: ").append(alert.getMessage()).append("\n\n");
            
            if (alert.getDetails() != null && !alert.getDetails().isEmpty()) {
                body.append("Additional Details:\n");
                alert.getDetails().forEach((key, value) -> 
                    body.append("- ").append(key).append(": ").append(value).append("\n")
                );
            }
            
            body.append("\n---\n");
            body.append("This is an automated security alert from MCP System.\n");
            body.append("Please investigate immediately if this is a CRITICAL or HIGH severity alert.\n");
            
            message.setText(body.toString());
            
            mailSender.send(message);
            log.info("Security alert email sent: {}", alert.getTitle());
            
        } catch (Exception e) {
            log.error("Failed to send security alert email", e);
        }
    }
    
    /**
     * Check if alert type is throttled
     */
    private boolean isThrottled(String alertKey) {
        LocalDateTime lastAlert = lastAlertTimes.get(alertKey);
        if (lastAlert == null) {
            return false;
        }
        
        return lastAlert.isAfter(LocalDateTime.now().minusMinutes(ALERT_THROTTLE_MINUTES));
    }
    
    /**
     * Update alert throttling
     */
    private void updateAlertThrottle(SecurityAlert alert) {
        String key = alert.getSeverity() + "_" + alert.getTitle().hashCode();
        lastAlertTimes.put(key, LocalDateTime.now());
    }
    
    /**
     * Send Slack notification
     */
    private void sendSlackNotification(SecurityAlert alert) {
        if (slackWebhook == null || slackWebhook.trim().isEmpty()) {
            log.debug("Slack webhook not configured");
            return;
        }
        
        try {
            var slackMessage = Map.of(
                "text", String.format("[%s] %s", alert.getSeverity(), alert.getTitle()),
                "attachments", List.of(Map.of(
                    "color", getSlackColor(alert.getSeverity()),
                    "fields", List.of(
                        Map.of("title", "Severity", "value", alert.getSeverity().name(), "short", true),
                        Map.of("title", "Time", "value", alert.getTimestamp().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME), "short", true),
                        Map.of("title", "Message", "value", alert.getMessage(), "short", false)
                    )
                ))
            );
            
            restTemplate.postForEntity(slackWebhook, slackMessage, String.class);
            log.debug("Alert sent to Slack: {}", alert.getTitle());
        } catch (Exception e) {
            log.error("Failed to send alert to Slack", e);
        }
    }
    
    /**
     * Send Microsoft Teams notification
     */
    private void sendTeamsNotification(SecurityAlert alert) {
        if (teamsWebhook == null || teamsWebhook.trim().isEmpty()) {
            log.debug("Teams webhook not configured");
            return;
        }
        
        try {
            var teamsMessage = Map.of(
                "@type", "MessageCard",
                "@context", "https://schema.org/extensions",
                "themeColor", getTeamsColor(alert.getSeverity()),
                "summary", alert.getTitle(),
                "sections", List.of(Map.of(
                    "activityTitle", alert.getTitle(),
                    "activitySubtitle", "Security Alert - " + alert.getSeverity(),
                    "facts", List.of(
                        Map.of("name", "Severity", "value", alert.getSeverity().name()),
                        Map.of("name", "Time", "value", alert.getTimestamp().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)),
                        Map.of("name", "Message", "value", alert.getMessage())
                    ),
                    "markdown", true
                ))
            );
            
            restTemplate.postForEntity(teamsWebhook, teamsMessage, String.class);
            log.debug("Alert sent to Teams: {}", alert.getTitle());
        } catch (Exception e) {
            log.error("Failed to send alert to Teams", e);
        }
    }
    
    private String getSlackColor(AlertSeverity severity) {
        return switch (severity) {
            case CRITICAL -> "danger";
            case HIGH -> "warning";
            case MEDIUM -> "warning";
            case LOW -> "good";
            case INFO -> "#36a64f";
        };
    }
    
    private String getTeamsColor(AlertSeverity severity) {
        return switch (severity) {
            case CRITICAL -> "ff0000";
            case HIGH -> "ff8c00";
            case MEDIUM -> "ffd700";
            case LOW -> "32cd32";
            case INFO -> "0078d4";
        };
    }
    
    /**
     * Format message for Slack
     */
    private String formatSlackMessage(SecurityAlert alert) {
        StringBuilder sb = new StringBuilder();
        sb.append("*").append(alert.getTitle()).append("*\n");
        sb.append(alert.getMessage()).append("\n");
        sb.append("*Severity:* ").append(alert.getSeverity()).append("\n");
        sb.append("*Time:* ").append(alert.getTimestamp().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)).append("\n");
        
        if (alert.getDetails() != null && !alert.getDetails().isEmpty()) {
            sb.append("*Details:*\n");
            alert.getDetails().forEach((key, value) -> 
                sb.append("• ").append(key).append(": ").append(value).append("\n"));
        }
        
        return sb.toString();
    }
    
    /**
     * Get emoji for severity level
     */
    private String getSeverityEmoji(AlertSeverity severity) {
        return switch (severity) {
            case CRITICAL -> ":rotating_light:";
            case HIGH -> ":warning:";
            case MEDIUM -> ":exclamation:";
            case LOW -> ":information_source:";
            case INFO -> ":blue_book:";
        };
    }
    
    /**
     * Get color for severity level
     */
    private String getSeverityColor(AlertSeverity severity) {
        return switch (severity) {
            case CRITICAL -> "FF0000"; // Red
            case HIGH -> "FF8C00"; // Dark Orange
            case MEDIUM -> "FFD700"; // Gold
            case LOW -> "008000"; // Green
            case INFO -> "0078D4"; // Blue
        };
    }
    
    public enum AlertSeverity {
        CRITICAL, HIGH, MEDIUM, LOW, INFO
    }
    
    @lombok.Data
    @lombok.Builder
    public static class SecurityAlert {
        private AlertSeverity severity;
        private String title;
        private String message;
        private Map<String, String> details;
        private LocalDateTime timestamp;
    }
    
    public static class SecurityAlertEvent {
        private final SecurityAlert alert;
        
        public SecurityAlertEvent(SecurityAlert alert) {
            this.alert = alert;
        }
        
        public SecurityAlert getAlert() {
            return alert;
        }
    }
}