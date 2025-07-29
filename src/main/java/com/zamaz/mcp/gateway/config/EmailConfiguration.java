package com.zamaz.mcp.gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.util.Properties;

/**
 * Email configuration for the MCP Gateway service.
 * Configures JavaMailSender for SMTP email sending.
 * 
 * Example configuration in application.yml:
 * 
 * spring:
 *   mail:
 *     host: smtp.gmail.com
 *     port: 587
 *     username: your-email@gmail.com
 *     password: your-app-password
 *     properties:
 *       mail:
 *         smtp:
 *           auth: true
 *           starttls:
 *             enable: true
 *             required: true
 *           connectiontimeout: 5000
 *           timeout: 5000
 *           writetimeout: 5000
 * 
 * app:
 *   email:
 *     enabled: true
 *     from: noreply@yourcompany.com
 *     from-name: Your Company Name
 *     base-url: https://yourapp.com
 */
@Configuration
@ConditionalOnProperty(name = "app.email.enabled", havingValue = "true")
public class EmailConfiguration {

    @Value("${spring.mail.host:}")
    private String mailHost;

    @Value("${spring.mail.port:587}")
    private int mailPort;

    @Value("${spring.mail.username:}")
    private String mailUsername;

    @Value("${spring.mail.password:}")
    private String mailPassword;

    @Value("${spring.mail.protocol:smtp}")
    private String mailProtocol;

    @Value("${spring.mail.properties.mail.smtp.auth:true}")
    private boolean smtpAuth;

    @Value("${spring.mail.properties.mail.smtp.starttls.enable:true}")
    private boolean starttlsEnable;

    @Value("${spring.mail.properties.mail.smtp.starttls.required:true}")
    private boolean starttlsRequired;

    @Value("${spring.mail.properties.mail.smtp.connectiontimeout:5000}")
    private int connectionTimeout;

    @Value("${spring.mail.properties.mail.smtp.timeout:5000}")
    private int timeout;

    @Value("${spring.mail.properties.mail.smtp.writetimeout:5000}")
    private int writeTimeout;

    /**
     * Configure JavaMailSender with SMTP settings.
     * This bean is only created when app.email.enabled=true
     */
    @Bean
    @ConditionalOnProperty(name = "app.email.enabled", havingValue = "true")
    public JavaMailSender javaMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        
        // Basic configuration
        mailSender.setHost(mailHost);
        mailSender.setPort(mailPort);
        mailSender.setUsername(mailUsername);
        mailSender.setPassword(mailPassword);
        mailSender.setProtocol(mailProtocol);
        
        // Additional properties
        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.smtp.auth", smtpAuth);
        props.put("mail.smtp.starttls.enable", starttlsEnable);
        props.put("mail.smtp.starttls.required", starttlsRequired);
        props.put("mail.smtp.connectiontimeout", connectionTimeout);
        props.put("mail.smtp.timeout", timeout);
        props.put("mail.smtp.writetimeout", writeTimeout);
        
        // For debugging email issues
        props.put("mail.debug", false);
        
        // Additional properties for different providers
        if (mailHost.contains("gmail")) {
            props.put("mail.smtp.ssl.protocols", "TLSv1.2");
            props.put("mail.smtp.ssl.trust", "smtp.gmail.com");
        } else if (mailHost.contains("outlook") || mailHost.contains("office365")) {
            props.put("mail.smtp.ssl.protocols", "TLSv1.2");
            props.put("mail.smtp.ssl.trust", mailHost);
        }
        
        return mailSender;
    }
    
    /**
     * Email provider presets for common services
     */
    public static class EmailProviderPresets {
        
        public static Properties getGmailProperties() {
            Properties props = new Properties();
            props.put("mail.smtp.host", "smtp.gmail.com");
            props.put("mail.smtp.port", "587");
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.starttls.required", "true");
            props.put("mail.smtp.ssl.protocols", "TLSv1.2");
            props.put("mail.smtp.ssl.trust", "smtp.gmail.com");
            return props;
        }
        
        public static Properties getOutlookProperties() {
            Properties props = new Properties();
            props.put("mail.smtp.host", "smtp-mail.outlook.com");
            props.put("mail.smtp.port", "587");
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.starttls.required", "true");
            props.put("mail.smtp.ssl.protocols", "TLSv1.2");
            return props;
        }
        
        public static Properties getSendGridProperties() {
            Properties props = new Properties();
            props.put("mail.smtp.host", "smtp.sendgrid.net");
            props.put("mail.smtp.port", "587");
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.username", "apikey");
            // Password should be the SendGrid API key
            return props;
        }
        
        public static Properties getAwsSesProperties(String region) {
            Properties props = new Properties();
            props.put("mail.smtp.host", String.format("email-smtp.%s.amazonaws.com", region));
            props.put("mail.smtp.port", "587");
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.starttls.required", "true");
            return props;
        }
    }
}