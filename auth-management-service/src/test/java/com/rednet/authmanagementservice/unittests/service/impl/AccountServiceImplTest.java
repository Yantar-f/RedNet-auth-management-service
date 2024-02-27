package com.rednet.authmanagementservice.unittests.service.impl;

import com.rednet.authmanagementservice.client.AccountServiceClient;
import com.rednet.authmanagementservice.entity.Account;
import com.rednet.authmanagementservice.exception.OccupiedValueException;
import com.rednet.authmanagementservice.exception.ServerErrorException;
import com.rednet.authmanagementservice.model.AccountCreationData;
import com.rednet.authmanagementservice.model.AccountUniqueFields;
import com.rednet.authmanagementservice.model.AccountUniqueFieldsOccupancy;
import com.rednet.authmanagementservice.service.AccountService;
import com.rednet.authmanagementservice.service.impl.AccountServiceImpl;
import feign.FeignException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Optional;

import static org.instancio.Instancio.create;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AccountServiceImplTest {
    private final AccountServiceClient client = mock(AccountServiceClient.class);
    private final AccountService sut = new AccountServiceImpl(client);

    private static final List<Class<? extends FeignException>> clientExceptions = List.of(
            FeignException.FeignClientException.class,
            FeignException.FeignServerException.class,
            FeignException.BadRequest.class,
            FeignException.NotFound.class,
            FeignException.BadGateway.class,
            FeignException.Conflict.class,
            FeignException.Gone.class,
            FeignException.InternalServerError.class,
            FeignException.MethodNotAllowed.class,
            FeignException.NotAcceptable.class,
            FeignException.Forbidden.class,
            FeignException.GatewayTimeout.class,
            FeignException.NotImplemented.class,
            FeignException.ServiceUnavailable.class,
            FeignException.TooManyRequests.class,
            FeignException.Unauthorized.class,
            FeignException.UnprocessableEntity.class,
            FeignException.UnsupportedMediaType.class
    );

    @Test
    public void Creating_account_is_successful() {
        AccountCreationData creationData = create(AccountCreationData.class);
        Account expectedAccount = create(Account.class);

        when(client.createAccount(eq(creationData)))
                .thenReturn(ResponseEntity.ok(expectedAccount));

        Account actualAccount = sut.createAccount(creationData);

        assertEquals(expectedAccount, actualAccount);

        verify(client).createAccount(eq(creationData));
    }

    @Test
    public void Creating_account_with_occupied_field_values_is_not_successful() {
        AccountCreationData creationData = create(AccountCreationData.class);

        when(client.createAccount(eq(creationData)))
                .thenThrow(FeignException.Conflict.class);

        assertThrows(OccupiedValueException.class, () -> sut.createAccount(creationData));

        verify(client).createAccount(eq(creationData));
    }

    @ParameterizedTest
    @MethodSource("creatingAccountUnexpectedErrors")
    public void Creating_account_with_unexpected_error_is_not_successful(
            Class<? extends FeignException> exceptinoClass) {

        AccountCreationData creationData = create(AccountCreationData.class);

        when(client.createAccount(eq(creationData)))
                .thenThrow(exceptinoClass);

        assertThrows(ServerErrorException.class, () -> sut.createAccount(creationData));

        verify(client).createAccount(eq(creationData));
    }

    private static List<Class<? extends FeignException>> creatingAccountUnexpectedErrors() {
        return clientExceptions.stream()
                .filter(aClass -> ! aClass.equals(FeignException.Conflict.class))
                .toList();
    }

    @Test
    public void Finding_account_by_username_or_email_is_successful() {
        String username = create(String.class);
        String email = create(String.class);
        Account expectedAccount = create(Account.class);

        when(client.getAccountByUsernameOrEmail(eq(username), eq(email)))
                .thenReturn(ResponseEntity.ok(expectedAccount));

        Optional<Account> actualAccount = sut.findAccountByUsernameOrEmail(username, email);

        assertTrue(actualAccount.isPresent());
        assertEquals(expectedAccount, actualAccount.get());
    }

    @Test
    public void Finding_not_existing_account_by_username_or_email_is_not_successful() {
        String username = create(String.class);
        String email = create(String.class);

        when(client.getAccountByUsernameOrEmail(eq(username), eq(email)))
                .thenThrow(FeignException.NotFound.class);

        Optional<Account> actualAccount = sut.findAccountByUsernameOrEmail(username, email);

        assertTrue(actualAccount.isEmpty());
    }

    @ParameterizedTest
    @MethodSource("findingAccountUnexpectedErrors")
    public void Finding_account_by_username_or_email_with_unexpected_error_is_not_successful(
            Class<? extends FeignException> exceptinoClass) {

        String username = create(String.class);
        String email = create(String.class);

        when(client.getAccountByUsernameOrEmail(eq(username), eq(email)))
                .thenThrow(exceptinoClass);

        assertThrows(ServerErrorException.class, () -> sut.findAccountByUsernameOrEmail(username, email));
    }

    private static List<Class<? extends FeignException>> findingAccountUnexpectedErrors() {
        return clientExceptions.stream()
                .filter(aClass -> ! aClass.equals(FeignException.NotFound.class))
                .toList();
    }

    @Test
    public void Getting_account_unique_fields_occupancy_is_successful() {
        AccountUniqueFields uniqueFields = create(AccountUniqueFields.class);
        AccountUniqueFieldsOccupancy expectedOccupancy = create(AccountUniqueFieldsOccupancy.class);

        when(client.getAccountUniqueFieldsOccupancy(eq(uniqueFields.username()), eq(uniqueFields.email())))
                .thenReturn(ResponseEntity.ok(expectedOccupancy));

        AccountUniqueFieldsOccupancy actualOccuapncy = sut.getAccountUniqueFieldsOccupancy(uniqueFields);

        assertEquals(expectedOccupancy, actualOccuapncy);
    }

    @ParameterizedTest
    @MethodSource("gettingAccountUniqueFieldsOccupancyUnexpectedErrors")
    public void Getting_account_unique_fields_occupancy_with_unexpected_error_is_not_successful(
            Class<? extends FeignException> exceptinoClass) {

        AccountUniqueFields uniqueFields = create(AccountUniqueFields.class);

        when(client.getAccountUniqueFieldsOccupancy(eq(uniqueFields.username()), eq(uniqueFields.email())))
                .thenThrow(exceptinoClass);

        assertThrows(ServerErrorException.class, () -> sut.getAccountUniqueFieldsOccupancy(uniqueFields));
    }

    private static List<Class<? extends FeignException>> gettingAccountUniqueFieldsOccupancyUnexpectedErrors() {
        return clientExceptions;
    }
}
