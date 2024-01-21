package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.client.AccountServiceClient;
import com.rednet.authmanagementservice.entity.Account;
import com.rednet.authmanagementservice.exception.OccupiedValueException;
import com.rednet.authmanagementservice.exception.ServerErrorException;
import com.rednet.authmanagementservice.model.AccountCreationData;
import com.rednet.authmanagementservice.model.AccountUniqueFields;
import com.rednet.authmanagementservice.model.AccountUniqueFieldsOccupancy;
import com.rednet.authmanagementservice.service.AccountService;
import feign.FeignException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AccountServiceImpl implements AccountService {
    private final AccountServiceClient serviceClient;

    public AccountServiceImpl(AccountServiceClient serviceClient) {
        this.serviceClient = serviceClient;
    }

    @Override
    public Account createAccount(AccountCreationData creationData) {
        Account account = serviceClient.createAccount(creationData).getBody();

        try {
            return Optional
                    .ofNullable(account)
                    .orElseThrow(() -> new ServerErrorException("Error finding account"));
        } catch (FeignException.Conflict exception) {
            throw new OccupiedValueException("Some unique fields are already occupied");
        }
    }

    @Override
    public Optional<Account> findAccountByUsernameOrEmail(String username, String email) {
        Account account = serviceClient.getAccountByUsernameOrEmail(username, email).getBody();

        try {
            return Optional.of(Optional
                    .ofNullable(account)
                    .orElseThrow(() -> new ServerErrorException("Error finding account")));
        } catch (FeignException.NotFound exception) {
            return Optional.empty();
        }
    }

    @Override
    public AccountUniqueFieldsOccupancy checkAccountUniqueFieldsOccupancy(AccountUniqueFields fields) {
        var occupancy = serviceClient.getAccountUniqueFieldsOccupancy(fields.username(), fields.email()).getBody();

        return Optional
                .ofNullable(occupancy)
                .orElseThrow(() -> new ServerErrorException("Error finding account"));
    }
}
