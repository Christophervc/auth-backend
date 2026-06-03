package com.vc.auth_backend.modules.auth.service;

import com.vc.auth_backend.modules.user.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.core.type.TypeReference;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class BackupCodeService {

    private final PasswordEncoder passwordEncoder;
    private final JsonMapper jsonMapper;

    private static final int BACKUP_CODE_COUNT = 8;
    private static final int BACKUP_CODE_LENGTH = 10;
    private static final String CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    public record BackupCodePair(List<String> plain, List<String> hashed) {}

    public BackupCodePair generateBackupCodes() {
        List<String> plain = new ArrayList<>();
        List<String> hashed = new ArrayList<>();
        SecureRandom rng = new SecureRandom();

        for (int i = 0; i < BACKUP_CODE_COUNT; i++) {
            String code = generateRandomAlphanumeric(rng, BACKUP_CODE_LENGTH);
            plain.add(code);
            hashed.add(passwordEncoder.encode(code));
        }
        return new BackupCodePair(plain, hashed);
    }

    public boolean consumeBackupCode(User user, String providedCode) {
        String backupCodesJson = user.getBackupCodesJson();
        if (backupCodesJson == null || backupCodesJson.isBlank()) {
            return false;
        }

        List<String> hashes = deserialize(backupCodesJson);
        for (int i = 0; i < hashes.size(); i++) {
            if (passwordEncoder.matches(providedCode, hashes.get(i))) {
                hashes.remove(i); // Invalida el código (de un solo uso)
                user.setBackupCodesJson(serialize(hashes)); // Actualiza la entidad, pero no hace save en DB
                return true;
            }
        }
        return false;
    }

    public String serialize(List<String> hashes) {
        try {
            return jsonMapper.writeValueAsString(hashes);
        } catch (Exception e) {
            log.error("Error serializing backup codes", e);
            throw new IllegalStateException("Error serializing backup codes", e);
        }
    }

    private List<String> deserialize(String json) {
        try {
            return jsonMapper.readValue(json, new TypeReference<>() {});
        } catch (Exception e) {
            log.error("Error deserializing backup codes", e);
            throw new IllegalStateException("Error deserializing backup codes", e);
        }
    }

    private String generateRandomAlphanumeric(SecureRandom rng, int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(CHARACTERS.charAt(rng.nextInt(CHARACTERS.length())));
        }
        return sb.toString();
    }
}
