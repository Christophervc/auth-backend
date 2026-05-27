package com.vc.auth_backend.modules.media;

import com.vc.auth_backend.modules.media.dto.ImageUploadResponse;
import com.vc.auth_backend.shared.exception.ExternalServiceUnavailableException;
import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class ImageService {

    private final Cloudinary cloudinary;

    private static final Set<String> ALLOWED_TYPES = Set.of(
            "image/jpeg", "image/png", "image/webp", "image/gif"
    );
    private static final long MAX_SIZE_BYTES = 5 * 1024 * 1024;

    public ImageUploadResponse uploadImage(MultipartFile file, String folderName) {
        String contentType = file.getContentType();
        if (contentType == null || !ALLOWED_TYPES.contains(contentType)) {
            throw new IllegalArgumentException("File type not allowed. Use JPEG, PNG, WEBP or GIF");
        }
        if (file.getSize() > MAX_SIZE_BYTES) {
            throw new IllegalArgumentException("File size exceeds the 5MB limit");
        }

        try {
            Map<String, Object> uploadParams = ObjectUtils.asMap(
                    "folder", "auth_backend/" + (folderName != null ? folderName : "general"),
                    "public_id", UUID.randomUUID().toString(),
                    "overwrite", "true",
                    "resource_type", "image"
                    );

            Map<?, ?> uploadResult = cloudinary.uploader().upload(file.getBytes(), uploadParams);

            String secureUrl = uploadResult.get("secure_url").toString();
            String publicId = uploadResult.get("public_id").toString();

            return new ImageUploadResponse(secureUrl, publicId);

        } catch (IOException e) {
            log.error("Error processing the file before uploading it to Cloudinary: {}", e.getMessage());
            throw new IllegalArgumentException("The file provided could not be read");
        } catch (Exception e) {
            log.error("Upload failed to Cloudinary: {}", e.getMessage());
            throw new ExternalServiceUnavailableException("The image upload service is temporarily unavailable.");
        }
    }

    public void deleteImageByPublicId(String publicId) {
        try {
            if (publicId != null && !publicId.isEmpty()) {
                cloudinary.uploader().destroy(publicId, ObjectUtils.emptyMap());
                log.info("Asset successfully removed from Cloudinary: {}", publicId);
            }
        } catch (Exception e) {
            log.error("Failed to remove asset from Cloudinary [ID: {}]: {}", publicId, e.getMessage());
        }
    }
}
