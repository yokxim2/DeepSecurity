package org.example.deepsecurity.repository;

import org.example.deepsecurity.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    boolean existsByUsername(String username);
    UserEntity findByUsername(String username);
}
