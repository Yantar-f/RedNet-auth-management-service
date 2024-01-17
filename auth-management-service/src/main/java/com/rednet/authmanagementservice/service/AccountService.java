package com.rednet.authmanagementservice.service;

import com.rednet.authmanagementservice.entity.Account;
import com.rednet.authmanagementservice.model.AccountCreationData;
import com.rednet.authmanagementservice.model.AccountUniqueFields;
import com.rednet.authmanagementservice.model.AccountUniqueFieldsOccupancy;

import java.util.Optional;

public interface AccountService {

    Account createAccount(AccountCreationData creationData);
    Optional<Account> findAccountByUsernameOrEmail(String username, String email);
    AccountUniqueFieldsOccupancy checkAccountUniqueFieldsOccupancy(AccountUniqueFields uniqueFields);
}
