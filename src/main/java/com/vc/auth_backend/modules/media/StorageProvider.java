package com.vc.auth_backend.modules.media;

import com.vc.auth_backend.modules.media.dto.ImageUploadResponse;

/**
 * Contrato para proveedores de almacenamiento de archivos.
 * Permite desacoplar la lógica de negocio del proveedor concreto (Cloudinary, S3, etc.).
 * Para migrar de proveedor basta con crear una nueva implementación de esta interfaz
 * y marcarla con {@code @Primary}.
 */
public interface StorageProvider {

    ImageUploadResponse upload(byte[] fileBytes, String folder, String filenameHint);

    void delete(String publicId);
}
