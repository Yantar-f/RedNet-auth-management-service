package com.rednet.authmanagementservice.repository;

import com.rednet.authmanagementservice.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    boolean existsByDesignation(String designation);
}
