package com.vc.auth_backend.modules.user.repository;

import com.vc.auth_backend.modules.user.entity.User;
import org.jspecify.annotations.NonNull;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);
    @NonNull Page<User> findAll(@NonNull Pageable pageable);
}
