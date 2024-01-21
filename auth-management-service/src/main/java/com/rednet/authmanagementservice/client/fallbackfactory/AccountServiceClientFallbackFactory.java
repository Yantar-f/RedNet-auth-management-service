package com.rednet.authmanagementservice.client.fallbackfactory;

import com.rednet.authmanagementservice.client.AccountServiceClient;
import com.rednet.authmanagementservice.entity.Account;
import com.rednet.authmanagementservice.exception.ServerErrorException;
import com.rednet.authmanagementservice.model.AccountCreationData;
import com.rednet.authmanagementservice.model.AccountUniqueFieldsOccupancy;
import feign.FeignException;
import org.springframework.cloud.openfeign.FallbackFactory;
import org.springframework.http.ResponseEntity;

public class AccountServiceClientFallbackFactory implements FallbackFactory<AccountServiceClient> {
    @Override
    public AccountServiceClient create(Throwable cause) {
        return new AccountServiceClient() {
            @Override
            public ResponseEntity<Account> createAccount(AccountCreationData data) {
                if (cause instanceof FeignException.Conflict exception) {
                    throw exception;
                } else {
                    throw new ServerErrorException("Error during creating account");
                }
            }

            @Override
            public ResponseEntity<Account> getAccountByUsernameOrEmail(String username, String email) {
                if (cause instanceof FeignException.NotFound exception) {
                    throw exception;
                } else {
                    throw new ServerErrorException("Error during getting account");
                }
            }

            @Override
            public ResponseEntity<AccountUniqueFieldsOccupancy> getAccountUniqueFieldsOccupancy(String username, String email) {
                throw new ServerErrorException("Error during getting account unique fields occupancy");
            }
        };
    }
}
