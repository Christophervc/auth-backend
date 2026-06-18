package com.vc.auth_backend.modules.user.service;

import com.vc.auth_backend.modules.auth.security.CustomUserPrincipal;
import com.vc.auth_backend.modules.user.controller.dto.ChangePasswordReq;
import com.vc.auth_backend.modules.user.controller.dto.PublicUserResponse;
import com.vc.auth_backend.modules.user.controller.dto.UpdateUserProfileReq;
import com.vc.auth_backend.modules.user.controller.dto.UserResponse;
import com.vc.auth_backend.modules.user.entity.Role;
import com.vc.auth_backend.modules.user.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;

import java.util.UUID;

public interface UserService {
    User getUserById(UUID id);
    UserResponse getUserResponseById(UUID id);
    Page<UserResponse> getAllUsers(CustomUserPrincipal currentUser, Pageable pageable);
    UserResponse updateUserStatus(UUID targetId, boolean active, CustomUserPrincipal currentUser);
    UserResponse updateUserRole(UUID targetId, Role newRole, CustomUserPrincipal currentUser);
    UserResponse updateMyProfile(UUID userId, UpdateUserProfileReq request);
    PublicUserResponse getPublicProfile(UUID userId);
    void changePassword(UUID userId, ChangePasswordReq request);
    void deactivateAccount(CustomUserPrincipal currentUser);
    UserResponse updateAvatar(UUID userId, MultipartFile file);
    void deleteAvatar(UUID userId);
}
