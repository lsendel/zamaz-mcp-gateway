package com.zamaz.mcp.gateway.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

/**
 * Email service for sending user management related emails.
 * Supports both SMTP and fallback logging when email is disabled.
 * Configure SMTP settings in application properties for production use.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    @Value("${app.email.base-url:http://localhost:3000}")
    private String baseUrl;
    
    @Value("${app.email.from:noreply@mcp.com}")
    private String fromAddress;
    
    @Value("${app.email.from-name:MCP Platform}")
    private String fromName;
    
    @Value("${app.email.enabled:false}")
    private boolean emailEnabled;
    
    @Value("${app.email.provider:smtp}")
    private String emailProvider;
    
    @Autowired(required = false)
    private JavaMailSender mailSender;

    /**
     * Send email verification message
     */
    public void sendEmailVerification(String toEmail, String firstName, String verificationToken) {
        String subject = "Verify Your Email Address - MCP Platform";
        String verificationUrl = baseUrl + "/verify-email?token=" + verificationToken;
        
        String htmlContent = buildEmailVerificationTemplate(firstName, verificationUrl);
        String textContent = buildEmailVerificationTextTemplate(firstName, verificationUrl);
        
        sendEmail(toEmail, subject, htmlContent, textContent);
        
        log.info("Email verification sent to: {} with token: {}", toEmail, verificationToken.substring(0, 8) + "...");
    }

    /**
     * Send password reset email
     */
    public void sendPasswordReset(String toEmail, String firstName, String resetToken) {
        String subject = "Reset Your Password - MCP Platform";
        String resetUrl = baseUrl + "/reset-password?token=" + resetToken;
        
        String htmlContent = buildPasswordResetTemplate(firstName, resetUrl);
        String textContent = buildPasswordResetTextTemplate(firstName, resetUrl);
        
        sendEmail(toEmail, subject, htmlContent, textContent);
        
        log.info("Password reset email sent to: {} with token: {}", toEmail, resetToken.substring(0, 8) + "...");
    }

    /**
     * Send welcome email after successful registration
     */
    public void sendWelcomeEmail(String toEmail, String firstName) {
        String subject = "Welcome to MCP Platform!";
        
        String htmlContent = buildWelcomeTemplate(firstName);
        String textContent = buildWelcomeTextTemplate(firstName);
        
        sendEmail(toEmail, subject, htmlContent, textContent);
        
        log.info("Welcome email sent to: {}", toEmail);
    }

    /**
     * Send account deactivation notification
     */
    public void sendAccountDeactivationNotification(String toEmail, String firstName) {
        String subject = "Account Deactivated - MCP Platform";
        
        String htmlContent = buildAccountDeactivationTemplate(firstName);
        String textContent = buildAccountDeactivationTextTemplate(firstName);
        
        sendEmail(toEmail, subject, htmlContent, textContent);
        
        log.info("Account deactivation notification sent to: {}", toEmail);
    }

    /**
     * Send email change notification
     */
    public void sendEmailChangeNotification(String oldEmail, String newEmail, String firstName) {
        String subject = "Email Address Changed - MCP Platform";
        
        String htmlContent = buildEmailChangeTemplate(firstName, newEmail);
        String textContent = buildEmailChangeTextTemplate(firstName, newEmail);
        
        // Send to both old and new email addresses
        sendEmail(oldEmail, subject, htmlContent, textContent);
        sendEmail(newEmail, subject, htmlContent, textContent);
        
        log.info("Email change notification sent to: {} and {}", oldEmail, newEmail);
    }

    private void sendEmail(String toEmail, String subject, String htmlContent, String textContent) {
        if (!emailEnabled) {
            log.info("Email sending disabled. Would send email to: {}", toEmail);
            log.debug("Email subject: {}", subject);
            log.debug("Email content: {}", textContent);
            return;
        }
        
        if (mailSender == null) {
            log.error("Email enabled but JavaMailSender not configured. Please configure spring.mail properties.");
            return;
        }
        
        try {
            switch (emailProvider.toLowerCase()) {
                case "smtp":
                    sendSmtpEmail(toEmail, subject, htmlContent, textContent);
                    break;
                case "sendgrid":
                    sendSendGridEmail(toEmail, subject, htmlContent, textContent);
                    break;
                case "ses":
                    sendAwsSesEmail(toEmail, subject, htmlContent, textContent);
                    break;
                default:
                    sendSmtpEmail(toEmail, subject, htmlContent, textContent);
            }
            
            log.info("Email sent successfully to: {} with subject: {}", toEmail, subject);
            
        } catch (Exception e) {
            log.error("Failed to send email to: {} with subject: {}", toEmail, subject, e);
            throw new EmailSendException("Failed to send email", e);
        }
    }
    
    /**
     * Send email using SMTP (works with Gmail, Outlook, custom SMTP servers)
     */
    private void sendSmtpEmail(String toEmail, String subject, String htmlContent, String textContent) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        
        try {
            helper.setFrom(fromAddress, fromName);
        } catch (Exception e) {
            // Fallback to simple from address if name causes issues
            helper.setFrom(fromAddress);
        }
        
        helper.setTo(toEmail);
        helper.setSubject(subject);
        
        // Set both HTML and plain text versions
        if (htmlContent != null) {
            helper.setText(textContent, htmlContent);
        } else {
            helper.setText(textContent);
        }
        
        mailSender.send(message);
    }
    
    /**
     * Send email using SendGrid API (requires additional integration)
     */
    private void sendSendGridEmail(String toEmail, String subject, String htmlContent, String textContent) {
        // SendGrid integration would go here
        // For now, fallback to SMTP
        log.info("SendGrid integration not implemented, falling back to SMTP");
        try {
            sendSmtpEmail(toEmail, subject, htmlContent, textContent);
        } catch (MessagingException e) {
            throw new EmailSendException("Failed to send email via SMTP fallback", e);
        }
    }
    
    /**
     * Send email using AWS SES (requires additional integration)
     */
    private void sendAwsSesEmail(String toEmail, String subject, String htmlContent, String textContent) {
        // AWS SES integration would go here
        // For now, fallback to SMTP
        log.info("AWS SES integration not implemented, falling back to SMTP");
        try {
            sendSmtpEmail(toEmail, subject, htmlContent, textContent);
        } catch (MessagingException e) {
            throw new EmailSendException("Failed to send email via SMTP fallback", e);
        }
    }
    
    /**
     * Custom exception for email sending failures
     */
    public static class EmailSendException extends RuntimeException {
        public EmailSendException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private String buildEmailVerificationTemplate(String firstName, String verificationUrl) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Verify Your Email</title>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #007bff; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background-color: #f8f9fa; }
                    .button { display: inline-block; padding: 12px 24px; background-color: #28a745; color: white; text-decoration: none; border-radius: 4px; }
                    .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>MCP Platform</h1>
                    </div>
                    <div class="content">
                        <h2>Welcome %s!</h2>
                        <p>Thank you for registering with MCP Platform. To complete your registration, please verify your email address by clicking the button below:</p>
                        <p style="text-align: center;">
                            <a href="%s" class="button">Verify Email Address</a>
                        </p>
                        <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
                        <p><a href="%s">%s</a></p>
                        <p>This verification link will expire in 24 hours.</p>
                        <p>If you didn't create an account with us, please ignore this email.</p>
                    </div>
                    <div class="footer">
                        <p>© 2025 MCP Platform. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(firstName, verificationUrl, verificationUrl, verificationUrl);
    }

    private String buildEmailVerificationTextTemplate(String firstName, String verificationUrl) {
        return """
            Welcome %s!
            
            Thank you for registering with MCP Platform. To complete your registration, please verify your email address by visiting the following link:
            
            %s
            
            This verification link will expire in 24 hours.
            
            If you didn't create an account with us, please ignore this email.
            
            Best regards,
            The MCP Platform Team
            """.formatted(firstName, verificationUrl);
    }

    private String buildPasswordResetTemplate(String firstName, String resetUrl) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Reset Your Password</title>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #007bff; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background-color: #f8f9fa; }
                    .button { display: inline-block; padding: 12px 24px; background-color: #dc3545; color: white; text-decoration: none; border-radius: 4px; }
                    .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
                    .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; border-radius: 4px; margin: 10px 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>MCP Platform</h1>
                    </div>
                    <div class="content">
                        <h2>Password Reset Request</h2>
                        <p>Hello %s,</p>
                        <p>We received a request to reset your password for your MCP Platform account. Click the button below to create a new password:</p>
                        <p style="text-align: center;">
                            <a href="%s" class="button">Reset Password</a>
                        </p>
                        <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
                        <p><a href="%s">%s</a></p>
                        <div class="warning">
                            <strong>Security Notice:</strong> This password reset link will expire in 1 hour. If you didn't request a password reset, please ignore this email and your password will remain unchanged.
                        </div>
                    </div>
                    <div class="footer">
                        <p>© 2025 MCP Platform. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(firstName, resetUrl, resetUrl, resetUrl);
    }

    private String buildPasswordResetTextTemplate(String firstName, String resetUrl) {
        return """
            Password Reset Request
            
            Hello %s,
            
            We received a request to reset your password for your MCP Platform account. Visit the following link to create a new password:
            
            %s
            
            This password reset link will expire in 1 hour.
            
            If you didn't request a password reset, please ignore this email and your password will remain unchanged.
            
            Best regards,
            The MCP Platform Team
            """.formatted(firstName, resetUrl);
    }

    private String buildWelcomeTemplate(String firstName) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Welcome to MCP Platform</title>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #28a745; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background-color: #f8f9fa; }
                    .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Welcome to MCP Platform!</h1>
                    </div>
                    <div class="content">
                        <h2>Hello %s!</h2>
                        <p>Your email has been successfully verified and your account is now active.</p>
                        <p>You can now access all the features of MCP Platform:</p>
                        <ul>
                            <li>Create and participate in debates</li>
                            <li>Manage your organization settings</li>
                            <li>Access advanced AI-powered features</li>
                        </ul>
                        <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
                    </div>
                    <div class="footer">
                        <p>© 2025 MCP Platform. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(firstName);
    }

    private String buildWelcomeTextTemplate(String firstName) {
        return """
            Welcome to MCP Platform!
            
            Hello %s!
            
            Your email has been successfully verified and your account is now active.
            
            You can now access all the features of MCP Platform:
            - Create and participate in debates
            - Manage your organization settings
            - Access advanced AI-powered features
            
            If you have any questions or need assistance, please don't hesitate to contact our support team.
            
            Best regards,
            The MCP Platform Team
            """.formatted(firstName);
    }

    private String buildAccountDeactivationTemplate(String firstName) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Account Deactivated</title>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #dc3545; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background-color: #f8f9fa; }
                    .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Account Deactivated</h1>
                    </div>
                    <div class="content">
                        <h2>Hello %s,</h2>
                        <p>Your MCP Platform account has been deactivated as requested.</p>
                        <p>If you change your mind and would like to reactivate your account, please contact our support team.</p>
                        <p>Thank you for using MCP Platform.</p>
                    </div>
                    <div class="footer">
                        <p>© 2025 MCP Platform. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(firstName);
    }

    private String buildAccountDeactivationTextTemplate(String firstName) {
        return """
            Account Deactivated
            
            Hello %s,
            
            Your MCP Platform account has been deactivated as requested.
            
            If you change your mind and would like to reactivate your account, please contact our support team.
            
            Thank you for using MCP Platform.
            
            Best regards,
            The MCP Platform Team
            """.formatted(firstName);
    }

    private String buildEmailChangeTemplate(String firstName, String newEmail) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Email Address Changed</title>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #ffc107; color: black; padding: 20px; text-align: center; }
                    .content { padding: 20px; background-color: #f8f9fa; }
                    .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
                    .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; border-radius: 4px; margin: 10px 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Email Address Changed</h1>
                    </div>
                    <div class="content">
                        <h2>Hello %s,</h2>
                        <p>The email address for your MCP Platform account has been changed to: <strong>%s</strong></p>
                        <div class="warning">
                            <strong>Security Notice:</strong> If you didn't make this change, please contact our support team immediately.
                        </div>
                        <p>You will need to verify your new email address to continue using all platform features.</p>
                    </div>
                    <div class="footer">
                        <p>© 2025 MCP Platform. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(firstName, newEmail);
    }

    private String buildEmailChangeTextTemplate(String firstName, String newEmail) {
        return """
            Email Address Changed
            
            Hello %s,
            
            The email address for your MCP Platform account has been changed to: %s
            
            If you didn't make this change, please contact our support team immediately.
            
            You will need to verify your new email address to continue using all platform features.
            
            Best regards,
            The MCP Platform Team
            """.formatted(firstName, newEmail);
    }
}