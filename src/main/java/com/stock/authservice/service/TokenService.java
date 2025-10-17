package com.stock.authservice.service;

import com.stock.authservice.entity.RefreshToken;
import com.stock.authservice.entity.User;
import com.stock.authservice.exception.TokenExpiredException;
import com.stock.authservice.exception.TokenInvalidException;
import com.stock.authservice.repository.RefreshTokenRepository;
import com.stock.authservice.security.JwtTokenProvider;
import com.stock.authservice.util.DateTimeUtil;
import com.stock.authservice.util.RandomTokenGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;

    // ==================== REFRESH TOKEN MANAGEMENT ====================

    @Transactional
    public RefreshToken createRefreshToken(User user, String ipAddress, String userAgent) {
        log.info("Creating refresh token for user: {}", user.getUsername());

        // Invalidate old refresh tokens for this user (optional: keep last N tokens)
        refreshTokenRepository.deleteByUserId(user.getId());

        String token = RandomTokenGenerator.generateSecureToken(64);

        RefreshToken refreshToken = RefreshToken.builder()
                .token(token)
                .user(user)
                .expiresAt(DateTimeUtil.addDays(LocalDateTime.now(), 7)) // 7 days
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .isRevoked(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional(readOnly = true)
    public RefreshToken validateRefreshToken(String token) {
        log.debug("Validating refresh token");

        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new TokenInvalidException("Invalid refresh token"));

        if (refreshToken.getIsRevoked()) {
            log.warn("Attempted to use revoked refresh token");
            throw new TokenInvalidException("Refresh token has been revoked");
        }

        if (refreshToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("Attempted to use expired refresh token");
            throw new TokenExpiredException("Refresh token has expired");
        }

        return refreshToken;
    }

    @Transactional
    public void revokeRefreshToken(String token) {
        log.info("Revoking refresh token");

        Optional<RefreshToken> refreshTokenOpt = refreshTokenRepository.findByToken(token);

        if (refreshTokenOpt.isPresent()) {
            RefreshToken refreshToken = refreshTokenOpt.get();
            refreshToken.setIsRevoked(true);
            refreshToken.setRevokedAt(LocalDateTime.now());
            refreshTokenRepository.save(refreshToken);
            log.info("Refresh token revoked successfully");
        }
    }

    @Transactional
    public void revokeAllUserRefreshTokens(String userId) {
        log.info("Revoking all refresh tokens for user: {}", userId);

        refreshTokenRepository.findByUserId(userId).forEach(token -> {
            token.setIsRevoked(true);
            token.setRevokedAt(LocalDateTime.now());
            refreshTokenRepository.save(token);
        });
    }

    @Transactional
    public void cleanupExpiredTokens() {
        log.info("Cleaning up expired refresh tokens");

        LocalDateTime now = LocalDateTime.now();
        int deletedCount = refreshTokenRepository.deleteByExpiresAtBefore(now);

        log.info("Deleted {} expired refresh tokens", deletedCount);
    }

    // ==================== PASSWORD RESET TOKEN ====================

    public String generatePasswordResetToken() {
        return RandomTokenGenerator.generatePasswordResetToken();
    }

    public String generateEmailVerificationToken() {
        return RandomTokenGenerator.generateEmailVerificationToken();
    }

    // ==================== MFA TEMP TOKEN ====================

    public String generateMfaTempToken(String username) {
        return jwtTokenProvider.generateMfaTempToken(username);
    }

    public boolean validateMfaTempToken(String token) {
        try {
            jwtTokenProvider.validateToken(token);
            return true;
        } catch (Exception e) {
            log.error("MFA temp token validation failed: {}", e.getMessage());
            return false;
        }
    }

    public String getUsernameFromMfaTempToken(String token) {
        return jwtTokenProvider.getUsernameFromToken(token);
    }
}
