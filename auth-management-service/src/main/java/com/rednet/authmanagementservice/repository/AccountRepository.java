package com.rednet.authmanagementservice.repository;

import com.rednet.authmanagementservice.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AccountRepository extends JpaRepository<Account, String> {
    Optional<Account> findByUsernameOrEmail(String username, String email);

    Optional<Account> findEagerByUsernameOrEmail(String username, String email);
}
