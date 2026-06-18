package com.vc.auth_backend.modules.media;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import com.vc.auth_backend.modules.media.dto.ImageUploadResponse;
import com.vc.auth_backend.shared.exception.ExternalServiceUnavailableException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Map;

@Slf4j
@Service
@Primary
@RequiredArgsConstructor
public class CloudinaryStorageProvider implements StorageProvider {

    private final Cloudinary cloudinary;

    private static final String BASE_FOLDER = "auth_backend/";

    @Override
    @SuppressWarnings("unchecked")
    public ImageUploadResponse upload(byte[] fileBytes, String folder, String filenameHint) {
        try {
            Map<String, Object> params = ObjectUtils.asMap(
                    "folder",        BASE_FOLDER + folder,
                    "public_id",     filenameHint,
                    "overwrite",     true,
                    "resource_type", "image"
            );

            Map<?, ?> result = cloudinary.uploader().upload(fileBytes, params);

            String secureUrl = result.get("secure_url").toString();
            String publicId  = result.get("public_id").toString();

            log.info("Asset uploaded to Cloudinary: publicId={}", publicId);
            return new ImageUploadResponse(secureUrl, publicId);

        } catch (IOException e) {
            log.error("Error reading file bytes before Cloudinary upload: {}", e.getMessage());
            throw new IllegalArgumentException("The file provided could not be read");
        } catch (Exception e) {
            log.error("Cloudinary upload failed: {}", e.getMessage());
            throw new ExternalServiceUnavailableException("The image upload service is temporarily unavailable.");
        }
    }

    @Override
    public void delete(String publicId) {
        if (publicId == null || publicId.isBlank()) return;
        try {
            cloudinary.uploader().destroy(publicId, ObjectUtils.emptyMap());
            log.info("Asset deleted from Cloudinary: publicId={}", publicId);
        } catch (Exception e) {
            log.error("Failed to delete asset from Cloudinary [publicId={}]: {}", publicId, e.getMessage());
        }
    }
}
