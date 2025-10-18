package com.stock.authservice.controller;

import com.stock.authservice.dto.request.MfaEnableRequest;
import com.stock.authservice.dto.request.MfaVerifyRequest;
import com.stock.authservice.dto.response.ApiResponse;
import com.stock.authservice.dto.response.MfaSetupResponse;
import com.stock.authservice.service.MfaService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/mfa")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "MFA Management", description = "Multi-Factor Authentication endpoints")
@SecurityRequirement(name = "Bearer Authentication")
public class MfaController {

    private final MfaService mfaService;

    // ==================== ENABLE MFA ====================

    @PostMapping("/enable")
    @Operation(summary = "Enable MFA", description = "Initiate MFA setup for user")
    public ResponseEntity<ApiResponse<MfaSetupResponse>> enableMfa(
            @Valid @RequestBody MfaEnableRequest request,
            Authentication authentication) {
        log.info("POST /api/mfa/enable - Enable MFA for user: {}", authentication.getName());

        ApiResponse<MfaSetupResponse> response = mfaService.enableMfa(request, authentication.getName());

        return ResponseEntity.ok(response);
    }

    // ==================== VERIFY AND ACTIVATE MFA ====================

    @PostMapping("/verify")
    @Operation(summary = "Verify MFA code", description = "Verify MFA code to complete setup")
    public ResponseEntity<ApiResponse<Void>> verifyMfa(
            @Valid @RequestBody MfaVerifyRequest request,
            Authentication authentication) {
        log.info("POST /api/mfa/verify - Verify MFA code for user: {}", authentication.getName());

        ApiResponse<Void> response = mfaService.verifyAndActivateMfa(request, authentication.getName());

        return ResponseEntity.ok(response);
    }

    // ==================== DISABLE MFA ====================

    @PostMapping("/disable")
    @Operation(summary = "Disable MFA", description = "Disable MFA for user")
    public ResponseEntity<ApiResponse<Void>> disableMfa(Authentication authentication) {
        log.info("POST /api/mfa/disable - Disable MFA for user: {}", authentication.getName());

        ApiResponse<Void> response = mfaService.disableMfa(authentication.getName());

        return ResponseEntity.ok(response);
    }

    // ==================== REGENERATE BACKUP CODES ====================

    @PostMapping("/backup-codes")
    @Operation(summary = "Regenerate backup codes", description = "Generate new MFA backup codes")
    public ResponseEntity<ApiResponse<List<String>>> regenerateBackupCodes(Authentication authentication) {
        log.info("POST /api/mfa/backup-codes - Regenerate backup codes for user: {}", authentication.getName());

        ApiResponse<List<String>> response = mfaService.regenerateBackupCodes(authentication.getName());

        return ResponseEntity.ok(response);
    }
}
