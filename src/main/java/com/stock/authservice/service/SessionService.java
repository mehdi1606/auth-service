package com.stock.authservice.service;

import com.stock.authservice.constants.SecurityConstants;
import com.stock.authservice.dto.response.SessionResponse;
import com.stock.authservice.entity.User;
import com.stock.authservice.entity.UserSession;
import com.stock.authservice.event.AuthEventPublisher;
import com.stock.authservice.event.dto.SessionCreatedEvent;
import com.stock.authservice.event.dto.SessionTerminatedEvent;
import com.stock.authservice.exception.ResourceNotFoundException;
import com.stock.authservice.repository.UserSessionRepository;
import com.stock.authservice.util.DateTimeUtil;
import com.stock.authservice.util.RandomTokenGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class SessionService {

    private final UserSessionRepository sessionRepository;
    private final AuthEventPublisher authEventPublisher;

    // ==================== CREATE SESSION ====================

    @Transactional
    public UserSession createSession(User user, String accessToken, String ipAddress, String userAgent, String deviceType) {
        log.info("Creating session for user: {}", user.getUsername());

        // Check max concurrent sessions
        List<UserSession> activeSessions = sessionRepository.findByUserIdAndIsActive(user.getId(), true);
        if (activeSessions.size() >= SecurityConstants.MAX_CONCURRENT_SESSIONS) {
            // Terminate oldest session
            UserSession oldestSession = activeSessions.stream()
                    .min((s1, s2) -> s1.getCreatedAt().compareTo(s2.getCreatedAt()))
                    .orElse(null);

            if (oldestSession != null) {
                terminateSession(oldestSession.getId(), "MAX_SESSIONS_EXCEEDED");
            }
        }

        String sessionToken = RandomTokenGenerator.generateSessionToken();

        UserSession session = UserSession.builder()
                .sessionToken(sessionToken)
                .user(user)
//                .accessToken(accessToken)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .deviceType(deviceType)
                .isActive(true)
                .lastActivity(LocalDateTime.now())
                .expiresAt(DateTimeUtil.addMinutes(LocalDateTime.now(), SecurityConstants.SESSION_INACTIVITY_TIMEOUT_MINUTES))
                .build();

        session = sessionRepository.save(session);

        // Publish event
        authEventPublisher.publishSessionCreated(SessionCreatedEvent.builder()
                .sessionId(session.getId())
                .userId(user.getId())
                .username(user.getUsername())
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .deviceType(deviceType)
                .createdAt(LocalDateTime.now())
                .expiresAt(session.getExpiresAt())
                .build());

        log.info("Session created for user: {}", user.getUsername());

        return session;
    }

    // ==================== UPDATE SESSION ACTIVITY ====================

    @Transactional
    public void updateSessionActivity(String sessionId) {
        sessionRepository.findById(sessionId).ifPresent(session -> {
            session.setLastActivity(LocalDateTime.now());
            session.setExpiresAt(DateTimeUtil.addMinutes(LocalDateTime.now(),
                    SecurityConstants.SESSION_INACTIVITY_TIMEOUT_MINUTES));
            sessionRepository.save(session);
        });
    }

    // ==================== TERMINATE SESSION ====================

    @Transactional
    public void terminateSession(String sessionId, String reason) {
        log.info("Terminating session: {} - Reason: {}", sessionId, reason);

        UserSession session = sessionRepository.findById(sessionId)
                .orElseThrow(() -> new ResourceNotFoundException("Session", "id", sessionId));

        session.setIsActive(false);
        sessionRepository.save(session);

        // Publish event
        authEventPublisher.publishSessionTerminated(SessionTerminatedEvent.builder()
                .sessionId(session.getId())
                .userId(session.getUser().getId())
                .username(session.getUser().getUsername())
                .terminationReason(reason)
                .terminatedAt(LocalDateTime.now())
                .build());

        log.info("Session terminated: {}", sessionId);
    }

    @Transactional
    public void terminateUserSessions(String userId, String reason) {
        log.info("Terminating all sessions for user: {}", userId);

        List<UserSession> activeSessions = sessionRepository.findByUserIdAndIsActive(userId, true);

        activeSessions.forEach(session -> terminateSession(session.getId(), reason));

        log.info("All sessions terminated for user: {}", userId);
    }

    // ==================== GET SESSIONS ====================

    @Transactional(readOnly = true)
    public List<SessionResponse> getUserSessions(String userId) {
        log.debug("Getting sessions for user: {}", userId);

        return sessionRepository.findByUserId(userId).stream()
                .map(this::mapToSessionResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<SessionResponse> getActiveSessions(String userId) {
        log.debug("Getting active sessions for user: {}", userId);

        return sessionRepository.findByUserIdAndIsActive(userId, true).stream()
                .map(this::mapToSessionResponse)
                .collect(Collectors.toList());
    }

    // ==================== CLEANUP EXPIRED SESSIONS ====================

    @Transactional
    public void cleanupExpiredSessions() {
        log.info("Cleaning up expired sessions");

        LocalDateTime now = LocalDateTime.now();
        List<UserSession> expiredSessions = sessionRepository.findByExpiresAtBeforeAndIsActive(now, true);

        expiredSessions.forEach(session -> terminateSession(session.getId(), "EXPIRED"));

        log.info("Cleaned up {} expired sessions", expiredSessions.size());
    }

    // ==================== MAPPER ====================

    private SessionResponse mapToSessionResponse(UserSession session) {
        return SessionResponse.builder()
                .id(session.getId())
                .sessionToken(session.getSessionToken())
                .ipAddress(session.getIpAddress())
                .userAgent(session.getUserAgent())
                .deviceType(session.getDeviceType())
                .isActive(session.getIsActive())
                .lastActivity(session.getLastActivity())
                .expiresAt(session.getExpiresAt())
                .createdAt(session.getCreatedAt())
                .build();
    }
}
