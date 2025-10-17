package com.stock.authservice.service;

import com.stock.authservice.constants.SecurityConstants;
import com.stock.authservice.dto.request.*;
import com.stock.authservice.dto.response.*;
import com.stock.authservice.entity.AuditLog;
import com.stock.authservice.entity.RefreshToken;
import com.stock.authservice.entity.UserSession;
import com.stock.authservice.entity.User;
import com.stock.authservice.event.AuthEventPublisher;
import com.stock.authservice.event.dto.*;
import com.stock.authservice.exception.*;
import com.stock.authservice.repository.UserRepository;
import com.stock.authservice.security.CustomUserDetails;
import com.stock.authservice.security.JwtTokenProvider;
import com.stock.authservice.util.DateTimeUtil;
import com.stock.authservice.util.IpAddressUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final TokenService tokenService;
    private final SessionService sessionService;
    private final AuditLogService auditLogService;
    private final AuthEventPublisher authEventPublisher;
    private final MfaService mfaService;
    private final UserService userService;

    // ==================== LOGIN ====================

    @Transactional
    public LoginResponse login(LoginRequest request, HttpServletRequest httpRequest) {
        log.info("Login attempt for user: {}", request.getUsernameOrEmail());

        String ipAddress = IpAddressUtil.getClientIpAddress(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        // Find user
        User user = userRepository.findByUsernameOrEmail(request.getUsernameOrEmail(), request.getUsernameOrEmail())
                .orElseThrow(() -> {
                    auditLogService.logFailedLogin(request.getUsernameOrEmail(), ipAddress, "User not found");
                    authEventPublisher.publishLoginFailed(UserLoginFailedEvent.builder()
                            .username(request.getUsernameOrEmail())
                            .ipAddress(ipAddress)
                            .userAgent(userAgent)
                            .failureReason("User not found")
                            .attemptTime(LocalDateTime.now())
                            .build());
                    return new InvalidCredentialsException();
                });

        // Check if account is locked
        if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(LocalDateTime.now())) {
            log.warn("Login attempt for locked account: {}", user.getUsername());
            throw new AccountLockedException(user.getLockedUntil());
        }

        // Check if account is active
        if (!user.getIsActive()) {
            log.warn("Login attempt for disabled account: {}", user.getUsername());
            throw new AccountDisabledException();
        }

        try {
            // Authenticate
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsernameOrEmail(),
                            request.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Reset failed login attempts
            if (user.getFailedLoginAttempts() > 0) {
                user.setFailedLoginAttempts(0);
                user.setLockedUntil(null);
                userRepository.save(user);
            }

            // Check if MFA is enabled
            if (user.getMfaEnabled()) {
                String tempToken = tokenService.generateMfaTempToken(user.getUsername());

                log.info("MFA required for user: {}", user.getUsername());

                return LoginResponse.builder()
                        .mfaRequired(true)
                        .tempToken(tempToken)
                        .build();
            }

            // Generate tokens
            String accessToken = jwtTokenProvider.generateAccessToken(authentication);
            RefreshToken refreshToken = tokenService.createRefreshToken(user, ipAddress, userAgent);

            // Create session
            UserSession session = sessionService.createSession(user, accessToken, ipAddress, userAgent, request.getDeviceType());

            // Update last login
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);

            // Audit log
            auditLogService.logSuccessfulLogin(user.getId(), user.getUsername(), ipAddress);

            // Publish event
            authEventPublisher.publishUserLogin(UserLoginEvent.builder()
                    .userId(user.getId())
                    .username(user.getUsername())
                    .email(user.getEmail())
                    .ipAddress(ipAddress)
                    .userAgent(userAgent)
                    .deviceType(request.getDeviceType())
                    .loginTime(LocalDateTime.now())
                    .mfaUsed(false)
                    .sessionId(session.getId())
                    .build());

            log.info("User logged in successfully: {}", user.getUsername());

            return LoginResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken.getToken())
                    .tokenType("Bearer")
                    .expiresIn(SecurityConstants.ACCESS_TOKEN_EXPIRATION / 1000) // seconds
                    .user(userService.mapToUserResponse(user))
                    .mfaRequired(false)
                    .build();

        } catch (Exception e) {
            // Increment failed login attempts
            handleFailedLogin(user, ipAddress, userAgent);
            throw new InvalidCredentialsException();
        }
    }

    // ==================== REGISTER ====================

    @Transactional
    public ApiResponse<UserResponse> register(RegisterRequest request) {
        log.info("Registration attempt for username: {}", request.getUsername());

        // Check if username exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new DuplicateResourceException("User", "username", request.getUsername());
        }

        // Check if email exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateResourceException("User", "email", request.getEmail());
        }

        // Check password match
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new PasswordMismatchException();
        }

        // Create user
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .phoneNumber(request.getPhoneNumber())
                .isActive(true)
                .isEmailVerified(false)
                .isPhoneVerified(false)
                .mfaEnabled(false)
                .failedLoginAttempts(0)
                .build();

        user = userRepository.save(user);

        // Assign default role (handled in UserService)
        userService.assignDefaultRole(user);

        // Generate email verification token
        String verificationToken = tokenService.generateEmailVerificationToken();
        user.setEmailVerificationToken(verificationToken);
        user.setEmailVerificationExpiry(DateTimeUtil.addHours(LocalDateTime.now(), 24));
        userRepository.save(user);

        // TODO: Send verification email (implement email service)

        log.info("User registered successfully: {}", user.getUsername());

        return ApiResponse.success("Registration successful. Please verify your email.",
                userService.mapToUserResponse(user));
    }

    // ==================== REFRESH TOKEN ====================

    @Transactional
    public TokenResponse refreshAccessToken(RefreshTokenRequest request, HttpServletRequest httpRequest) {
        log.info("Refresh token request");

        String ipAddress = IpAddressUtil.getClientIpAddress(httpRequest);

        // Validate refresh token
        RefreshToken refreshToken = tokenService.validateRefreshToken(request.getRefreshToken());

        User user = refreshToken.getUser();

        // Generate new access token
        CustomUserDetails userDetails = CustomUserDetails.build(user);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities()
        );

        String newAccessToken = jwtTokenProvider.generateAccessToken(authentication);

        // Optionally rotate refresh token
        tokenService.revokeRefreshToken(request.getRefreshToken());
        RefreshToken newRefreshToken = tokenService.createRefreshToken(
                user, ipAddress, httpRequest.getHeader("User-Agent")
        );

        log.info("Access token refreshed for user: {}", user.getUsername());

        return TokenResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken.getToken())
                .tokenType("Bearer")
                .expiresIn(SecurityConstants.ACCESS_TOKEN_EXPIRATION / 1000)
                .build();
    }

    // ==================== LOGOUT ====================

    @Transactional
    public ApiResponse<Void> logout(String accessToken, HttpServletRequest httpRequest) {
        log.info("Logout request");

        String username = jwtTokenProvider.getUsernameFromToken(accessToken);
        String ipAddress = IpAddressUtil.getClientIpAddress(httpRequest);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User", "username", username));

        // Revoke all refresh tokens
        tokenService.revokeAllUserRefreshTokens(user.getId());

        // Terminate active sessions
        sessionService.terminateUserSessions(user.getId(), "USER_LOGOUT");

        // Audit log
        auditLogService.logLogout(user.getId(), user.getUsername(), ipAddress);

        // Publish event
        authEventPublisher.publishUserLogout(UserLogoutEvent.builder()
                .userId(user.getId())
                .username(user.getUsername())
                .ipAddress(ipAddress)
                .logoutTime(LocalDateTime.now())
                .logoutReason("MANUAL")
                .build());

        log.info("User logged out successfully: {}", username);

        return ApiResponse.success("Logout successful", null);
    }

    // ==================== PASSWORD RESET ====================

    @Transactional
    public ApiResponse<Void> forgotPassword(PasswordResetRequest request) {
        log.info("Password reset request for email: {}", request.getEmail());

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResourceNotFoundException("User", "email", request.getEmail()));

        // Generate reset token
        String resetToken = tokenService.generatePasswordResetToken();
        user.setPasswordResetToken(resetToken);
        user.setPasswordResetExpiry(DateTimeUtil.addHours(LocalDateTime.now(), 1));
        userRepository.save(user);

        // TODO: Send password reset email

        // Publish event
        authEventPublisher.publishPasswordResetRequested(PasswordResetRequestedEvent.builder()
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .ipAddress(request.getIpAddress())
                .resetToken(resetToken)
                .requestedAt(LocalDateTime.now())
                .expiresAt(user.getPasswordResetExpiry())
                .build());

        log.info("Password reset email sent to: {}", request.getEmail());

        return ApiResponse.success("Password reset link has been sent to your email", null);
    }

    @Transactional
    public ApiResponse<Void> resetPassword(PasswordResetConfirmRequest request) {
        log.info("Password reset confirmation");

        User user = userRepository.findByPasswordResetToken(request.getToken())
                .orElseThrow(() -> new TokenInvalidException("Invalid reset token"));

        // Check token expiry
        if (user.getPasswordResetExpiry().isBefore(LocalDateTime.now())) {
            throw new TokenExpiredException("Password reset token has expired");
        }

        // Check password match
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new PasswordMismatchException();
        }

        // Update password
        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordResetToken(null);
        user.setPasswordResetExpiry(null);
        user.setPasswordChangedAt(LocalDateTime.now());
        userRepository.save(user);

        // Revoke all tokens and sessions
        tokenService.revokeAllUserRefreshTokens(user.getId());
        sessionService.terminateUserSessions(user.getId(), "PASSWORD_RESET");

        // Publish event
        authEventPublisher.publishPasswordChanged(PasswordChangedEvent.builder()
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .ipAddress(request.getIpAddress())
                .changedAt(LocalDateTime.now())
                .wasReset(true)
                .build());

        log.info("Password reset successfully for user: {}", user.getUsername());

        return ApiResponse.success("Password reset successful", null);
    }

    // ==================== CHANGE PASSWORD ====================

    @Transactional
    public ApiResponse<Void> changePassword(PasswordChangeRequest request, String username) {
        log.info("Password change request for user: {}", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User", "username", username));

        // Verify current password
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            throw new InvalidCredentialsException("Current password is incorrect");
        }

        // Check password match
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new PasswordMismatchException();
        }

        // Check if new password is same as current
        if (passwordEncoder.matches(request.getNewPassword(), user.getPasswordHash())) {
            throw new PasswordValidationException(
                    java.util.List.of("New password must be different from current password")
            );
        }

        // Update password
        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordChangedAt(LocalDateTime.now());
        userRepository.save(user);

        // Revoke all tokens except current
        tokenService.revokeAllUserRefreshTokens(user.getId());

        // Publish event
        authEventPublisher.publishPasswordChanged(PasswordChangedEvent.builder()
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .changedAt(LocalDateTime.now())
                .wasReset(false)
                .build());

        log.info("Password changed successfully for user: {}", username);

        return ApiResponse.success("Password changed successfully", null);
    }

    // ==================== EMAIL VERIFICATION ====================

    @Transactional
    public ApiResponse<Void> verifyEmail(String token) {
        log.info("Email verification request");

        User user = userRepository.findByEmailVerificationToken(token)
                .orElseThrow(() -> new TokenInvalidException("Invalid verification token"));

        // Check token expiry
        if (user.getEmailVerificationExpiry().isBefore(LocalDateTime.now())) {
            throw new TokenExpiredException("Email verification token has expired");
        }

        // Check if already verified
        if (user.getIsEmailVerified()) {
            throw new EmailAlreadyVerifiedException();
        }

        // Mark as verified
        user.setIsEmailVerified(true);
        user.setEmailVerificationToken(null);
        user.setEmailVerificationExpiry(null);
        userRepository.save(user);

        log.info("Email verified successfully for user: {}", user.getUsername());

        return ApiResponse.success("Email verified successfully", null);
    }

    // ==================== HELPER METHODS ====================

    private void handleFailedLogin(User user, String ipAddress, String userAgent) {
        user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);

        auditLogService.logFailedLogin(user.getUsername(), ipAddress, "Invalid credentials");

        if (user.getFailedLoginAttempts() >= SecurityConstants.MAX_FAILED_LOGIN_ATTEMPTS) {
            user.setLockedUntil(DateTimeUtil.addMinutes(LocalDateTime.now(),
                    SecurityConstants.ACCOUNT_LOCKOUT_DURATION_MINUTES));

            log.warn("Account locked due to failed login attempts: {}", user.getUsername());

            // Publish account locked event
            authEventPublisher.publishAccountLocked(AccountLockedEvent.builder()
                    .userId(user.getId())
                    .username(user.getUsername())
                    .email(user.getEmail())
                    .ipAddress(ipAddress)
                    .failedAttempts(user.getFailedLoginAttempts())
                    .lockedAt(LocalDateTime.now())
                    .lockedUntil(user.getLockedUntil())
                    .lockReason("Too many failed login attempts")
                    .build());
        }

        userRepository.save(user);

        // Publish failed login event
        authEventPublisher.publishLoginFailed(UserLoginFailedEvent.builder()
                .username(user.getUsername())
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .failureReason("Invalid credentials")
                .attemptCount(user.getFailedLoginAttempts())
                .attemptTime(LocalDateTime.now())
                .accountLocked(user.getLockedUntil() != null)
                .build());
    }
}
