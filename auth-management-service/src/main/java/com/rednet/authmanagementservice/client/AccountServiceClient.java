package com.rednet.authmanagementservice.client;

import com.rednet.authmanagementservice.client.fallbackfactory.AccountServiceClientFallbackFactory;
import com.rednet.authmanagementservice.entity.Account;
import com.rednet.authmanagementservice.model.AccountCreationData;
import com.rednet.authmanagementservice.model.AccountUniqueFieldsOccupancy;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@FeignClient(name = "ACCOUNT-SERVICE",
             path = "/accounts",
             fallbackFactory = AccountServiceClientFallbackFactory.class)
public interface AccountServiceClient {
    @PostMapping(consumes = APPLICATION_JSON_VALUE,
                 produces = APPLICATION_JSON_VALUE)
    ResponseEntity<Account> createAccount(AccountCreationData data);

    @GetMapping(path = "/by-username-or-email",
                produces = APPLICATION_JSON_VALUE)
    ResponseEntity<Account> getAccountByUsernameOrEmail(String username, String email);

    @GetMapping(path = "unique-fields-occupancy",
                produces = APPLICATION_JSON_VALUE)
    ResponseEntity<AccountUniqueFieldsOccupancy> getAccountUniqueFieldsOccupancy(@RequestParam String username,
                                                                                 @RequestParam String email);
}
