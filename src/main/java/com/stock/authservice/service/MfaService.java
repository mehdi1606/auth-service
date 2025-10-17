package com.stock.authservice.service;

import com.stock.authservice.constants.SecurityConstants;
import com.stock.authservice.dto.request.MfaEnableRequest;
import com.stock.authservice.dto.request.MfaVerifyRequest;
import com.stock.authservice.dto.response.ApiResponse;
import com.stock.authservice.dto.response.MfaSetupResponse;
import com.stock.authservice.entity.MfaSecret;
import com.stock.authservice.entity.User;
import com.stock.authservice.event.AuthEventPublisher;
import com.stock.authservice.event.dto.MfaDisabledEvent;
import com.stock.authservice.event.dto.MfaEnabledEvent;
import com.stock.authservice.exception.InvalidMfaCodeException;
import com.stock.authservice.exception.MfaAlreadyEnabledException;
import com.stock.authservice.exception.MfaNotEnabledException;
import com.stock.authservice.exception.ResourceNotFoundException;
import com.stock.authservice.repository.MfaSecretRepository;
import com.stock.authservice.repository.UserRepository;
import com.stock.authservice.security.SecurityContextHelper;
import com.stock.authservice.util.RandomTokenGenerator;
import dev.samstevens.totp.code.*;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class MfaService {

    private final UserRepository userRepository;
    private final MfaSecretRepository mfaSecretRepository;
    private final SecurityContextHelper securityContextHelper;
    private final AuthEventPublisher authEventPublisher;

    private final DefaultSecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator();
    private final CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

    // ==================== ENABLE MFA ====================

    @Transactional
    public ApiResponse<MfaSetupResponse> enableMfa(MfaEnableRequest request, String username) {
        log.info("Enabling MFA for user: {}", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User", "username", username));

        if (user.getMfaEnabled()) {
            throw new MfaAlreadyEnabledException();
        }

        // Generate secret
        String secret = secretGenerator.generate();

        // Create MFA secret entity
        MfaSecret mfaSecret = MfaSecret.builder()
                .user(user)
                .secret(secret)
                .mfaType(request.getMfaType())
                .isVerified(false) // Will be activated after verification
                .build();

        // Generate backup codes
        List<String> backupCodes = generateBackupCodes();
        mfaSecret.setBackupCodes(String.join(",", backupCodes));

        mfaSecretRepository.save(mfaSecret);

        // Generate QR code data
        String issuer = "StockManagement";
        QrData qrData = new QrData.Builder()
                .label(user.getEmail())
                .secret(secret)
                .issuer(issuer)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();

        // Generate QR code URL
        QrGenerator qrGenerator = new ZxingPngQrGenerator();
        String qrCodeUrl = null;
        try {
            byte[] imageData = qrGenerator.generate(qrData);
            qrCodeUrl = "data:image/png;base64," + java.util.Base64.getEncoder().encodeToString(imageData);
        } catch (Exception e) {
            log.error("Error generating QR code", e);
        }

        log.info("MFA setup initiated for user: {}", username);

        return ApiResponse.success("MFA setup initiated. Please scan QR code and verify.",
                MfaSetupResponse.builder()
                        .secret(secret)
                        .qrCodeUrl(qrCodeUrl)
                        .mfaType(request.getMfaType())
                        .backupCodes(backupCodes)
                        .message("Scan QR code with your authenticator app and enter the code to complete setup")
                        .build());
    }

    // ==================== VERIFY AND ACTIVATE MFA ====================

    @Transactional
    public ApiResponse<Void> verifyAndActivateMfa(MfaVerifyRequest request, String username) {
        log.info("Verifying MFA code for user: {}", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User", "username", username));

        MfaSecret mfaSecret = mfaSecretRepository.findByUserIdAndIsActive(user.getId(), false)
                .orElseThrow(() -> new MfaNotEnabledException("MFA setup not found. Please initiate setup first."));

        // Verify code
        boolean isValid = verifier.isValidCode(mfaSecret.getSecret(), request.getCode());

        if (!isValid) {
            log.warn("Invalid MFA code for user: {}", username);
            throw new InvalidMfaCodeException();
        }

        // Activate MFA
        mfaSecret.setIsVerified(true);
        mfaSecretRepository.save(mfaSecret);

        user.setMfaEnabled(true);
        userRepository.save(user);

        // Publish event
        authEventPublisher.publishMfaEnabled(MfaEnabledEvent.builder()
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .mfaType(mfaSecret.getMfaType())
                .enabledAt(LocalDateTime.now())
                .build());

        log.info("MFA enabled successfully for user: {}", username);

        return ApiResponse.success("MFA enabled successfully", null);
    }

    // ==================== VERIFY MFA CODE (DURING LOGIN) ====================

    @Transactional(readOnly = true)
    public boolean verifyMfaCode(String username, String code) {
        log.debug("Verifying MFA code during login for user: {}", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User", "username", username));

        if (!user.getMfaEnabled()) {
            throw new MfaNotEnabledException();
        }

        MfaSecret mfaSecret = mfaSecretRepository.findByUserIdAndIsVerified(user.getId(), true)
                .orElseThrow(() -> new MfaNotEnabledException("MFA secret not found"));

        // Check if it's a backup code
        if (isBackupCode(mfaSecret, code)) {
            log.info("Backup code used for user: {}", username);
            removeUsedBackupCode(mfaSecret, code);
            return true;
        }

        // Verify TOTP code
        boolean isValid = verifier.isValidCode(mfaSecret.getSecret(), code);

        if (!isValid) {
            log.warn("Invalid MFA code for user: {}", username);
            authEventPublisher.publishMfaVerifyFailed(username, null);
        } else {
            log.info("MFA code verified successfully for user: {}", username);
            authEventPublisher.publishMfaVerifySuccess(user.getId(), username);
        }

        return isValid;
    }

    // ==================== DISABLE MFA ====================

    @Transactional
    public ApiResponse<Void> disableMfa(String username) {
        log.info("Disabling MFA for user: {}", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User", "username", username));

        if (!user.getMfaEnabled()) {
            throw new MfaNotEnabledException();
        }

        // Deactivate MFA secrets
        mfaSecretRepository.findByUserId(user.getId()).forEach(secret -> {
            secret.setIsActive(false);
            mfaSecretRepository.save(secret);
        });

        user.setMfaEnabled(false);
        userRepository.save(user);

        // Publish event
        authEventPublisher.publishMfaDisabled(MfaDisabledEvent.builder()
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .disabledAt(LocalDateTime.now())
                .disabledBy(securityContextHelper.getCurrentUsername())
                .build());

        log.info("MFA disabled successfully for user: {}", username);

        return ApiResponse.success("MFA disabled successfully", null);
    }

    // ==================== REGENERATE BACKUP CODES ====================

    @Transactional
    public ApiResponse<List<String>> regenerateBackupCodes(String username) {
        log.info("Regenerating backup codes for user: {}", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User", "username", username));

        if (!user.getMfaEnabled()) {
            throw new MfaNotEnabledException();
        }

        MfaSecret mfaSecret = mfaSecretRepository.findByUserIdAndIsActive(user.getId(), true)
                .orElseThrow(() -> new MfaNotEnabledException("MFA secret not found"));

        // Generate new backup codes
        List<String> backupCodes = generateBackupCodes();
        mfaSecret.setBackupCodes(String.join(",", backupCodes));
        mfaSecretRepository.save(mfaSecret);

        log.info("Backup codes regenerated for user: {}", username);

        return ApiResponse.success("Backup codes regenerated successfully", backupCodes);
    }

    // ==================== HELPER METHODS ====================

    private List<String> generateBackupCodes() {
        List<String> codes = new ArrayList<>();
        for (int i = 0; i < SecurityConstants.MFA_BACKUP_CODES_COUNT; i++) {
            codes.add(RandomTokenGenerator.generateMfaBackupCode());
        }
        return codes;
    }

    private boolean isBackupCode(MfaSecret mfaSecret, String code) {
        if (mfaSecret.getBackupCodes() == null) {
            return false;
        }
        String[] codes = mfaSecret.getBackupCodes().split(",");
        for (String backupCode : codes) {
            if (backupCode.trim().equals(code)) {
                return true;
            }
        }
        return false;
    }

    @Transactional
    protected void removeUsedBackupCode(MfaSecret mfaSecret, String usedCode) {
        String[] codes = mfaSecret.getBackupCodes().split(",");
        List<String> remainingCodes = new ArrayList<>();

        for (String code : codes) {
            if (!code.trim().equals(usedCode)) {
                remainingCodes.add(code.trim());
            }
        }

        mfaSecret.setBackupCodes(String.join(",", remainingCodes));
        mfaSecretRepository.save(mfaSecret);

        log.info("Backup code removed. Remaining codes: {}", remainingCodes.size());
    }
}
