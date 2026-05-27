package com.vc.auth_backend.modules.user.service;

import com.vc.auth_backend.modules.auth.service.RefreshTokenService;
import com.vc.auth_backend.modules.auth.security.CustomUserPrincipal;
import com.vc.auth_backend.modules.user.controller.dto.ChangePasswordReq;
import com.vc.auth_backend.modules.user.controller.dto.PublicUserResponse;
import com.vc.auth_backend.modules.user.controller.dto.UpdateUserProfileReq;
import com.vc.auth_backend.modules.user.controller.dto.UserResponse;
import com.vc.auth_backend.modules.user.repository.UserRepository;
import com.vc.auth_backend.modules.user.entity.Role;
import com.vc.auth_backend.modules.user.entity.User;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;

    @Override
    public User getUserById(UUID id) {
        return userRepository
                .findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User not found with id: " + id));
    }

    @Override
    public UserResponse getUserResponseById(UUID id) {
        return toResponse(getUserById(id));
    }

    @Override
    public Page<UserResponse> getAllUsers(CustomUserPrincipal currentUser, Pageable pageable) {
        Role currentRole = currentUser.user().getRole();
        Page<User> usersPage;
        if (currentRole == Role.ADMIN) {
            usersPage = userRepository.findAll(pageable);
        } else {
            throw new AccessDeniedException("You do not have permission to list users");
        }
        return usersPage.map(this::toResponse);
    }

    @Override
    @Transactional
    public UserResponse updateUserStatus(UUID targetId, boolean active, CustomUserPrincipal currentUser) {
        User targetUser = getUserById(targetId);
        if (targetUser.getId().equals(currentUser.getId())) {
            throw new IllegalStateException("Cannot suspend your own account.");
        }
        targetUser.setActive(active);
        if (!active) {
            refreshTokenService.logoutAll(targetUser.getId());
        }
        return toResponse(targetUser);
    }

    @Override
    @Transactional
    public UserResponse updateUserRole(UUID targetId, Role newRole, CustomUserPrincipal currentUser) {
        User targetUser = getUserById(targetId);
        if (targetUser.getId().equals(currentUser.getId())) {
            throw new IllegalStateException("Cannot change your own user role");
        }
        targetUser.setRole(newRole);
        refreshTokenService.logoutAll(targetUser.getId());
        return toResponse(targetUser);
    }

    @Override
    @Transactional
    public UserResponse updateMyProfile(UUID userId, UpdateUserProfileReq request) {
        User user = getUserById(userId);
        user.setName(request.name());
        user.setLastname(request.bio());
        return toResponse(user);
    }

    @Override
    @Transactional(readOnly = true)
    public PublicUserResponse getPublicProfile(UUID userId) {
        User user = getUserById(userId);
        if (!user.isActive()) {
            throw new EntityNotFoundException("User profile not found or unavailable.");
        }
        return new PublicUserResponse(
                user.getId(),
                user.getName(),
                user.getLastname(),
                user.getJoinedAt()
        );
    }

    @Override
    @Transactional
    public void changePassword(UUID userId, ChangePasswordReq request) {
        User user = getUserById(userId);
        if (!passwordEncoder.matches(request.oldPassword(), user.getPassword())) {
            throw new BadCredentialsException("The current password is invalid");
        }
        refreshTokenService.logoutAll(user.getId());
        user.setPassword(passwordEncoder.encode(request.newPassword()));
    }

    @Override
    @Transactional
    public void deactivateAccount(CustomUserPrincipal currentUser) {
        User user = getUserById(currentUser.getId());
        if (user.getRole() == Role.ADMIN) {
            throw new IllegalStateException("An admin cannot deactivate their own account ");
        }
        user.setActive(false);
        refreshTokenService.logoutAll(user.getId()); // luego de desactivar mi cuenta cierro todas mis sesiones
        log.info("User {} has deactivate his/her account ", user.getEmail());
    }

    private UserResponse toResponse(User user) {
        return new UserResponse(
                user.getId(),
                user.getName(),
                user.getLastname(),
                user.getEmail(),
                user.getRole(),
                user.isActive(),
                user.getJoinedAt()
        );
    }

}
