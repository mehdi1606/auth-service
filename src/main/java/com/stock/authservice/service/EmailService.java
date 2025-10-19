package com.stock.authservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    // Stub implementation - Email functionality to be implemented later

    public void sendVerificationEmail(String email, String token) {
        log.info("Sending verification email to: {} with token: {}", email, token);
        // TODO: Implement email sending
    }

    public void sendPasswordResetEmail(String email, String token) {
        log.info("Sending password reset email to: {} with token: {}", email, token);
        // TODO: Implement email sending
    }

    public void sendWelcomeEmail(String email, String username) {
        log.info("Sending welcome email to: {}", email);
        // TODO: Implement email sending
    }
}
