package com.vc.auth_backend.modules.auth.scheduler;

import com.vc.auth_backend.modules.auth.repository.PasswordResetOtpRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Slf4j
@Component
@RequiredArgsConstructor
public class OtpCleanupScheduler {
    private final PasswordResetOtpRepository otpRepository;

    @Scheduled(cron = "0 0 3 * * *")
    @Transactional
    public void cleanExpiredOtps() {
        int deleted = otpRepository.deleteExpiredOtps(Instant.now());
        if (deleted > 0) {
            log.info("OTP cleanup: {} expired records deleted", deleted);
        } else {
            log.debug("OTP cleanup: no expired records found");
        }
    }
}
