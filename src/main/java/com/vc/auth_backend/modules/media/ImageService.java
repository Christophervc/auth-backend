package com.vc.auth_backend.modules.media;

import com.vc.auth_backend.modules.media.dto.ImageUploadResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class ImageService {

    private final StorageProvider storageProvider;
    private final AvatarValidator avatarValidator;

    private static final long MAX_AVATAR_SIZE_BYTES = 2L * 1024 * 1024;

    public ImageUploadResponse uploadAvatar(MultipartFile file, UUID userId) {
        validateSize(file, MAX_AVATAR_SIZE_BYTES, "2MB");
        byte[] originalBytes = readBytes(file);
        
        byte[] sanitizedBytes = avatarValidator.sanitize(originalBytes);
        
        String folder   = "avatars/" + userId;
        String filename = UUID.randomUUID().toString();
        return storageProvider.upload(sanitizedBytes, folder, filename);
    }

    public void deleteByPublicId(String publicId) {
        if (publicId == null || publicId.isBlank()) return;
        storageProvider.delete(publicId);
    }

    private void validateSize(MultipartFile file, long maxBytes, String label) {
        if (file.getSize() > maxBytes) {
            throw new IllegalArgumentException("File size exceeds the " + label + " limit");
        }
    }

    private byte[] readBytes(MultipartFile file) {
        try {
            return file.getBytes();
        } catch (IOException e) {
            log.error("Failed to read multipart file bytes: {}", e.getMessage());
            throw new IllegalArgumentException("The file provided could not be read");
        }
    }
}
