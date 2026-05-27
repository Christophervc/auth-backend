package com.vc.auth_backend.modules.media;

import com.vc.auth_backend.config.OpenApiConfig;
import com.vc.auth_backend.modules.media.dto.ImageUploadResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Set;

@RestController
@RequestMapping("/api/v1/media")
@RequiredArgsConstructor
@Tag(name = "Media", description = "Gestiona la carga y eliminacion de recursos multimedia.")
public class MediaController {
    private final ImageService imageService;
    // TODO: Subir y eliminar avatars
    @Operation(
            summary = "Subir imagen",
            description = "Carga una imagen en el proveedor de almacenamiento configurado. Requiere autenticacion y acepta cookie http-only o JWT bearer.",
            security = {
                    @SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME),
                    @SecurityRequirement(name = OpenApiConfig.COOKIE_SCHEME)
            }
    )
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ImageUploadResponse> uploadImage(
            @Parameter(description = "Archivo de imagen a subir.", required = true)
            @RequestParam("file") MultipartFile file,
            @Parameter(description = "Carpeta destino permitida: posts, avatars o covers.", example = "posts")
            @RequestParam(value = "folder", defaultValue = "posts") String folder) {
        Set<String> allowedFolders = Set.of("posts", "avatars", "covers");
        if (!allowedFolders.contains(folder)) {
            throw new IllegalArgumentException("Invalid folder. Allowed: posts, avatars, covers");
        }
        return ResponseEntity.ok(imageService.uploadImage(file, folder));
    }

//    @Operation(
//            summary = "Eliminar imagen de publicacion",
//            description = "Elimina una imagen asociada a una publicacion si el usuario autenticado tiene permisos sobre ella.",
//            security = {
//                    @SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME),
//                    @SecurityRequirement(name = OpenApiConfig.COOKIE_SCHEME)
//            }
//    )
//    @DeleteMapping("/{postId}/images/{imageId}")
//    public ResponseEntity<Void> deletePostImage(
//            @Parameter(hidden = true) @AuthenticationPrincipal CustomUserPrincipal currentUser) {
//        return ResponseEntity.noContent().build();
//    }
}
