package com.vc.auth_backend.modules.user.controller;

import com.vc.auth_backend.config.OpenApiConfig;
import com.vc.auth_backend.modules.auth.security.CustomUserPrincipal;
import com.vc.auth_backend.modules.user.controller.dto.*;
import com.vc.auth_backend.modules.user.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Tag(name = "Users", description = "Gestiona perfiles, administracion de usuarios")
public class UserController {
    private final UserService userService;

    @Operation(summary = "Obtener mi perfil", description = "Recupera el perfil completo del usuario autenticado.",
            security = {
                    @SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME),
                    @SecurityRequirement(name = OpenApiConfig.COOKIE_SCHEME)
            }
    )
    @GetMapping("/me")
    public ResponseEntity<UserResponse> getMyProfile(
            @Parameter(hidden = true) @AuthenticationPrincipal CustomUserPrincipal currentUser) {
        return ResponseEntity.ok(userService.getUserResponseById(currentUser.getId()));
    }

    @Operation(summary = "Listar usuarios", description = "Lista usuarios paginados. Requiere rol ADMIN o MODERATOR.",
            security = {
                    @SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME),
                    @SecurityRequirement(name = OpenApiConfig.COOKIE_SCHEME)
            }
    )
    @PreAuthorize("hasAnyRole('ADMIN')")
    @GetMapping
    public ResponseEntity<Page<UserResponse>> getAllUsers(
            @Parameter(hidden = true) @AuthenticationPrincipal CustomUserPrincipal currentUser,
            @Parameter(description = "Indice de pagina.", example = "0")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Cantidad de resultados por pagina.", example = "20")
            @RequestParam(defaultValue = "20") int size) {
        return ResponseEntity.ok(userService.getAllUsers(currentUser, PageRequest.of(page, size)));
    }

    @Operation(summary = "Actualizar estado de usuario", description = "Activa o desactiva un usuario por ID. Requiere rol ADMIN o MODERATOR.",
            security = {
                    @SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME),
                    @SecurityRequirement(name = OpenApiConfig.COOKIE_SCHEME)
            }
    )
    @PreAuthorize("hasAnyRole('ADMIN')")
    @PatchMapping("/{id}/status")
    public ResponseEntity<UserResponse> updateUserStatus(
            @Parameter(description = "ID del usuario a actualizar.")
            @PathVariable UUID id,
            @Valid @RequestBody UpdateUserStatusReq request,
            @Parameter(hidden = true) @AuthenticationPrincipal CustomUserPrincipal currentUser) {
        return ResponseEntity.ok(userService.updateUserStatus(id, request.active(), currentUser));
    }

    @Operation(summary = "Actualizar rol de usuario", description = "Cambia el rol de un usuario. Requiere rol ADMIN.",
            security = {
                    @SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME),
                    @SecurityRequirement(name = OpenApiConfig.COOKIE_SCHEME)
            }
    )
    @PreAuthorize("hasRole('ADMIN')")
    @PatchMapping("/{id}/role")
    public ResponseEntity<UserResponse> updateUserRole(
            @Parameter(description = "ID del usuario cuyo rol se desea actualizar.")
            @PathVariable UUID id,
            @Valid @RequestBody UpdateUserRoleReq request,
            @Parameter(hidden = true) @AuthenticationPrincipal CustomUserPrincipal currentUser
    ) {
        return ResponseEntity.ok(userService.updateUserRole(id, request.role(), currentUser));
    }

    @Operation(summary = "Actualizar mi perfil", description = "Actualiza parcialmente los datos editables del perfil del usuario autenticado.",
            security = {
                    @SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME),
                    @SecurityRequirement(name = OpenApiConfig.COOKIE_SCHEME)
            }
    )
    @PatchMapping("/me")
    public ResponseEntity<UserResponse> updateMyProfile(
            @Parameter(hidden = true) @AuthenticationPrincipal CustomUserPrincipal currentUser,
            @Valid @RequestBody UpdateUserProfileReq request) {
        return ResponseEntity.ok(userService.updateMyProfile(currentUser.getId(), request));
    }

    @Operation(summary = "Obtener perfil publico", description = "Recupera la informacion publica del autor indicado.")
    @GetMapping("/{id}/public")
    public ResponseEntity<PublicUserResponse> getPublicProfile(
            @Parameter(description = "ID del usuario a consultar.")
            @PathVariable UUID id) {
        return ResponseEntity.ok(userService.getPublicProfile(id));
    }

    @Operation(summary = "Cambiar mi contrasena", description = "Actualiza la contrasena del usuario autenticado.",
            security = {
                    @SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME),
                    @SecurityRequirement(name = OpenApiConfig.COOKIE_SCHEME)
            }
    )
    @PatchMapping("/me/change-password")
    public ResponseEntity<MessageResponse> changePassword(
            @Parameter(hidden = true) @AuthenticationPrincipal CustomUserPrincipal currentUser,
            @Valid @RequestBody ChangePasswordReq request) {
        userService.changePassword(currentUser.getId(), request);
        return ResponseEntity.ok(new MessageResponse("Password updated successfully"));
    }

    @Operation(summary = "Desactivar mi cuenta", description = "Desactiva la cuenta del usuario autenticado.",
            security = {
                    @SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME),
                    @SecurityRequirement(name = OpenApiConfig.COOKIE_SCHEME)
            }
    )
    @DeleteMapping("/me")
    public ResponseEntity<MessageResponse> deactivateAccount(
            @Parameter(hidden = true) @AuthenticationPrincipal CustomUserPrincipal currentUser) {
        userService.deactivateAccount(currentUser);
        return ResponseEntity.ok(new MessageResponse("Account deactivated successfully"));
    }

    @Operation(
            summary = "Subir o reemplazar avatar",
            description = "Sube una nueva foto de perfil. Si ya existía una, la elimina del proveedor de almacenamiento antes de subir la nueva. Límite: 2MB. Formatos: JPEG, PNG, WEBP, GIF.",
            security = {
                    @SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME),
                    @SecurityRequirement(name = OpenApiConfig.COOKIE_SCHEME)
            }
    )
    @PutMapping(value = "/me/avatar", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<UserResponse> updateAvatar(
            @Parameter(hidden = true) @AuthenticationPrincipal CustomUserPrincipal currentUser,
            @Parameter(description = "Archivo de imagen. Máx 2MB. Formatos: JPEG, PNG, WEBP, GIF.", required = true)
            @RequestParam("file") MultipartFile file) {
        return ResponseEntity.ok(userService.updateAvatar(currentUser.getId(), file));
    }

    @Operation(
            summary = "Eliminar avatar",
            description = "Elimina la foto de perfil del usuario autenticado. Si era una imagen subida por el sistema, también se elimina del proveedor de almacenamiento. Si era la foto de Google, solo se limpia la referencia local.",
            security = {
                    @SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME),
                    @SecurityRequirement(name = OpenApiConfig.COOKIE_SCHEME)
            }
    )
    @DeleteMapping("/me/avatar")
    public ResponseEntity<Void> deleteAvatar(
            @Parameter(hidden = true) @AuthenticationPrincipal CustomUserPrincipal currentUser) {
        userService.deleteAvatar(currentUser.getId());
        return ResponseEntity.noContent().build();
    }
}
