package com.stock.authservice.event;

import com.stock.authservice.constants.KafkaTopics;
import com.stock.authservice.event.dto.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Component;

import java.util.concurrent.CompletableFuture;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthEventPublisher {

    private final KafkaTemplate<String, Object> kafkaTemplate;

    // ==================== LOGIN EVENTS ====================

    public void publishUserLogin(UserLoginEvent event) {
        publishEvent(KafkaTopics.USER_LOGIN, event.getUserId(), event);
    }

    public void publishUserLogout(UserLogoutEvent event) {
        publishEvent(KafkaTopics.USER_LOGOUT, event.getUserId(), event);
    }

    public void publishLoginFailed(UserLoginFailedEvent event) {
        publishEvent(KafkaTopics.USER_LOGIN_FAILED, event.getUsername(), event);
    }

    // ==================== PASSWORD EVENTS ====================

    public void publishPasswordChanged(PasswordChangedEvent event) {
        publishEvent(KafkaTopics.PASSWORD_CHANGED, event.getUserId(), event);
    }

    public void publishPasswordResetRequested(PasswordResetRequestedEvent event) {
        publishEvent(KafkaTopics.PASSWORD_RESET_REQUESTED, event.getUserId(), event);
    }

    public void publishPasswordResetCompleted(PasswordChangedEvent event) {
        publishEvent(KafkaTopics.PASSWORD_RESET_COMPLETED, event.getUserId(), event);
    }

    // ==================== MFA EVENTS ====================

    public void publishMfaEnabled(MfaEnabledEvent event) {
        publishEvent(KafkaTopics.MFA_ENABLED, event.getUserId(), event);
    }

    public void publishMfaDisabled(MfaDisabledEvent event) {
        publishEvent(KafkaTopics.MFA_DISABLED, event.getUserId(), event);
    }

    public void publishMfaVerifySuccess(String userId, String username) {
        publishEvent(KafkaTopics.MFA_VERIFY_SUCCESS, userId,
                java.util.Map.of("userId", userId, "username", username, "timestamp", java.time.LocalDateTime.now()));
    }

    public void publishMfaVerifyFailed(String username, String ipAddress) {
        publishEvent(KafkaTopics.MFA_VERIFY_FAILED, username,
                java.util.Map.of("username", username, "ipAddress", ipAddress, "timestamp", java.time.LocalDateTime.now()));
    }

    // ==================== ACCOUNT EVENTS ====================

    public void publishAccountLocked(AccountLockedEvent event) {
        publishEvent(KafkaTopics.USER_LOCKED, event.getUserId(), event);
    }

    public void publishAccountUnlocked(String userId, String username) {
        publishEvent(KafkaTopics.USER_UNLOCKED, userId,
                java.util.Map.of("userId", userId, "username", username, "timestamp", java.time.LocalDateTime.now()));
    }

    // ==================== SESSION EVENTS ====================

    public void publishSessionCreated(SessionCreatedEvent event) {
        publishEvent(KafkaTopics.SESSION_CREATED, event.getUserId(), event);
    }

    public void publishSessionTerminated(SessionTerminatedEvent event) {
        publishEvent(KafkaTopics.SESSION_TERMINATED, event.getUserId(), event);
    }

    // ==================== HELPER METHOD ====================

    private void publishEvent(String topic, String key, Object event) {
        try {
            CompletableFuture<SendResult<String, Object>> future = kafkaTemplate.send(topic, key, event);

            future.whenComplete((result, ex) -> {
                if (ex == null) {
                    log.info("Published event to topic [{}] with key [{}]: offset={}",
                            topic, key, result.getRecordMetadata().offset());
                } else {
                    log.error("Failed to publish event to topic [{}] with key [{}]", topic, key, ex);
                }
            });

        } catch (Exception e) {
            log.error("Error publishing event to topic [{}]", topic, e);
        }
    }
}
