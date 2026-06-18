package com.vc.auth_backend.modules.media;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Iterator;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;

/**
 * Validador OWASP para avatares.
 * Implementa defensa en profundidad (Magic Bytes, validación de dimensiones y recodificación)
 * para sanitizar imágenes subidas por usuarios.
 */
@Slf4j
@Component
public class AvatarValidator {

    private static final int MAX_DIMENSION = 2000;

    // Firmas Magic Bytes comunes
    private static final byte[] MAGIC_JPEG = new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF};
    private static final byte[] MAGIC_PNG = new byte[]{(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    private static final byte[] MAGIC_GIF87A = new byte[]{0x47, 0x49, 0x46, 0x38, 0x37, 0x61};
    private static final byte[] MAGIC_GIF89A = new byte[]{0x47, 0x49, 0x46, 0x38, 0x39, 0x61};
    // WEBP es RIFF...WEBP
    private static final byte[] MAGIC_WEBP_PREFIX = new byte[]{0x52, 0x49, 0x46, 0x46}; // RIFF
    private static final byte[] MAGIC_WEBP_SUFFIX = new byte[]{0x57, 0x45, 0x42, 0x50}; // WEBP

    public byte[] sanitize(byte[] originalBytes) {
        if (originalBytes == null || originalBytes.length == 0) {
            throw new IllegalArgumentException("The provided file is empty.");
        }

        // Validación de Magic Bytes
        String formatName = getFormatFromMagicBytes(originalBytes);
        if (formatName == null) {
            throw new IllegalArgumentException("Invalid file format. Only JPEG, PNG, WEBP and GIF are allowed.");
        }

        // Decodificación y verificación de dimensiones para evitar Pixel Flood
        try (ByteArrayInputStream bais = new ByteArrayInputStream(originalBytes);
             ImageInputStream iis = ImageIO.createImageInputStream(bais)) {

            Iterator<ImageReader> readers = ImageIO.getImageReaders(iis);
            if (!readers.hasNext()) {
                throw new IllegalArgumentException("Cannot decode image. Invalid image file.");
            }

            ImageReader reader = readers.next();
            try {
                reader.setInput(iis, true, true);
                
                // Verificamos las dimensiones ANTES de cargar toda la imagen en memoria
                int width = reader.getWidth(0);
                int height = reader.getHeight(0);

                if (width > MAX_DIMENSION || height > MAX_DIMENSION) {
                    throw new IllegalArgumentException("Image dimensions exceed the allowed limit of " + MAX_DIMENSION + "x" + MAX_DIMENSION + "px.");
                }

                // Cargamos la imagen (si es GIF animado, lee solo el primer frame)
                BufferedImage image = reader.read(0);
                if (image == null) {
                    throw new IllegalArgumentException("Failed to decode image pixels.");
                }

                // Capa 3: Recodificación (Strip metadata y desarmar Polyglots)
                ByteArrayOutputStream baos = new ByteArrayOutputStream();

                String outputFormat = formatName.equals("WEBP") ? "PNG" : formatName;
                
                boolean wrote = ImageIO.write(image, outputFormat, baos);
                if (!wrote) {
                     // Fallback a PNG si el encoder falla
                     ImageIO.write(image, "PNG", baos);
                }

                byte[] sanitizedBytes = baos.toByteArray();
                log.debug("Image sanitized successfully. Original size: {} bytes, Sanitized size: {} bytes", originalBytes.length, sanitizedBytes.length);
                return sanitizedBytes;

            } finally {
                reader.dispose();
            }
        } catch (IOException e) {
            log.error("Error during image sanitization: {}", e.getMessage());
            throw new IllegalArgumentException("Corrupt or invalid image file.");
        }
    }

    private String getFormatFromMagicBytes(byte[] bytes) {
        if (startsWith(bytes, MAGIC_JPEG)) {
            return "JPEG";
        }
        if (startsWith(bytes, MAGIC_PNG)) {
            return "PNG";
        }
        if (startsWith(bytes, MAGIC_GIF87A) || startsWith(bytes, MAGIC_GIF89A)) {
            return "GIF";
        }
        if (bytes.length >= 12 && startsWith(bytes, MAGIC_WEBP_PREFIX)) {
            byte[] suffix = Arrays.copyOfRange(bytes, 8, 12);
            if (Arrays.equals(suffix, MAGIC_WEBP_SUFFIX)) {
                return "WEBP";
            }
        }
        return null;
    }

    private boolean startsWith(byte[] array, byte[] prefix) {
        if (array.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (array[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }
}
