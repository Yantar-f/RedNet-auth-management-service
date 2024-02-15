package com.rednet.unittests.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.client.RegistrationServiceClient;
import com.rednet.authmanagementservice.entity.Registration;
import com.rednet.authmanagementservice.exception.RegistrationNotFoundException;
import com.rednet.authmanagementservice.exception.ServerErrorException;
import com.rednet.authmanagementservice.model.RegistrationCreationData;
import com.rednet.authmanagementservice.service.RegistrationService;
import com.rednet.authmanagementservice.service.impl.RegistrationServiceImpl;
import feign.FeignException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Optional;

import static org.instancio.Instancio.create;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class RegistrationServiceImplTest {
    private final RegistrationServiceClient client = mock(RegistrationServiceClient.class);
    private final RegistrationService sut = new RegistrationServiceImpl(client);

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
    public void Creating_registration_is_successful() {
        RegistrationCreationData creationData = create(RegistrationCreationData.class);
        Registration expectedRegistration = create(Registration.class);

        when(client.createRegistration(eq(creationData)))
                .thenReturn(ResponseEntity.ok(expectedRegistration));

        Registration actualRegistration = sut.createRegistration(creationData);

        assertEquals(expectedRegistration, actualRegistration);

        verify(client).createRegistration(eq(creationData));
    }

    @ParameterizedTest
    @MethodSource("creatingRegistrationUnexpectedExceptions")
    public void Creating_registration_with_unexpected_error_is_not_successful(
            Class<? extends FeignException> exceptionClass) {
        RegistrationCreationData creationData = create(RegistrationCreationData.class);

        when(client.createRegistration(eq(creationData)))
                .thenThrow(exceptionClass);

        assertThrows(ServerErrorException.class, () -> sut.createRegistration(creationData));

        verify(client).createRegistration(eq(creationData));
    }

    private static List<Class<? extends FeignException>> creatingRegistrationUnexpectedExceptions() {
        return clientExceptions;
    }

    @Test
    public void Getting_registration_is_successful() {
        Registration expectedRegistration = create(Registration.class);

        when(client.getRegistrationByID(eq(expectedRegistration.getID())))
                .thenReturn(ResponseEntity.ok(expectedRegistration));

        Registration actualRegistration = sut
                .findRegistrationByID(expectedRegistration.getID())
                .orElseThrow(RuntimeException::new);

        assertEquals(expectedRegistration, actualRegistration);
    }

    @Test
    public void Getting_not_existing_registration_is_not_successful() {
        String expectedID = create(String.class);

        when(client.getRegistrationByID(eq(expectedID)))
                .thenThrow(FeignException.NotFound.class);

        Optional<Registration> optional = sut.findRegistrationByID(expectedID);

        assertTrue(optional.isEmpty());
    }

    @ParameterizedTest
    @MethodSource("gettingRegistrationUnexpectedExceptions")
    public void Getting_registration_with_unexpected_error_is_not_successful(
            Class<? extends FeignException> exceptionClass) {
        String expectedID = create(String.class);

        when(client.getRegistrationByID(eq(expectedID)))
                .thenThrow(exceptionClass);

        assertThrows(ServerErrorException.class, () -> sut.findRegistrationByID(expectedID));
    }

    private static List<Class<? extends FeignException>> gettingRegistrationUnexpectedExceptions() {
        return clientExceptions.stream()
                .filter(aClass -> ! aClass.equals(FeignException.NotFound.class))
                .toList();
    }

    @Test
    public void Updating_registration_is_successful() {
        Registration expectedUpdatedRegistration = create(Registration.class);

        when(client.updateRegistration(eq(expectedUpdatedRegistration)))
                .thenReturn(ResponseEntity.ok().build());

        sut.updateRegistration(expectedUpdatedRegistration);

        verify(client).updateRegistration(eq(expectedUpdatedRegistration));
    }

    @Test
    public void Updating_not_existing_registration_is_not_successful() {
        Registration expectedUpdatedRegistration = create(Registration.class);

        doThrow(FeignException.NotFound.class)
                .when(client).updateRegistration(eq(expectedUpdatedRegistration));

        assertThrows(
                RegistrationNotFoundException.class,
                () -> sut.updateRegistration(expectedUpdatedRegistration)
        );

        verify(client).updateRegistration(eq(expectedUpdatedRegistration));
    }

    @ParameterizedTest
    @MethodSource("updatingRegistrationUnexpectedExceptions")
    public void Updating_registration_with_unexpected_error_is_not_successful(
            Class<? extends FeignException> exceptionClass) {

        Registration expectedUpdatedRegistration = create(Registration.class);

        doThrow(exceptionClass)
                .when(client).updateRegistration(eq(expectedUpdatedRegistration));

        assertThrows(
                ServerErrorException.class,
                () -> sut.updateRegistration(expectedUpdatedRegistration)
        );

        verify(client).updateRegistration(eq(expectedUpdatedRegistration));
    }

    private static List<Class<? extends FeignException>> updatingRegistrationUnexpectedExceptions() {
        return clientExceptions.stream()
                .filter(aClass -> ! aClass.equals(FeignException.NotFound.class))
                .toList();
    }

    @Test
    public void Deleting_registration_is_successful() {
        String expectedID = create(String.class);

        when(client.deleteRegistrationByID(eq(expectedID)))
                .thenReturn(ResponseEntity.ok().build());

        sut.deleteRegistrationByID(expectedID);

        verify(client).deleteRegistrationByID(eq(expectedID));
    }

    @Test
    public void Deleting_not_existing_registration_is_not_successful() {
        String expectedID = create(String.class);

        doThrow(FeignException.NotFound.class)
                .when(client).deleteRegistrationByID(eq(expectedID));

        assertThrows(
                RegistrationNotFoundException.class,
                () -> sut.deleteRegistrationByID(expectedID)
        );

        verify(client).deleteRegistrationByID(eq(expectedID));
    }

    @ParameterizedTest
    @MethodSource("deletingRegistrationUnexpectedExceptions")
    public void Deleting_registration_with_unexpected_error_is_not_successful(
            Class<? extends FeignException> exceptionClass) {

        String expectedID = create(String.class);

        doThrow(exceptionClass)
                .when(client).deleteRegistrationByID(eq(expectedID));

        assertThrows(
                ServerErrorException.class,
                () -> sut.deleteRegistrationByID(expectedID)
        );

        verify(client).deleteRegistrationByID(eq(expectedID));
    }

    private static List<Class<? extends FeignException>> deletingRegistrationUnexpectedExceptions() {
        return clientExceptions.stream()
                .filter(aClass -> ! aClass.equals(FeignException.NotFound.class))
                .toList();
    }
}
