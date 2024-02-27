package com.rednet.authmanagementservice.unittests.service.impl;

import com.rednet.authmanagementservice.client.SessionServiceClient;
import com.rednet.authmanagementservice.config.RefreshTokenConfig;
import com.rednet.authmanagementservice.config.RolesEnum;
import com.rednet.authmanagementservice.entity.Session;
import com.rednet.authmanagementservice.exception.InvalidTokenException;
import com.rednet.authmanagementservice.exception.ServerErrorException;
import com.rednet.authmanagementservice.model.SessionCreationData;
import com.rednet.authmanagementservice.payload.request.RefreshSessionRequestBody;
import com.rednet.authmanagementservice.service.SessionService;
import com.rednet.authmanagementservice.service.impl.SessionServiceImpl;
import feign.FeignException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import static org.instancio.Instancio.create;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SessionServiceImplTest {
    private final SessionServiceClient sessionServiceClient = mock(SessionServiceClient.class);
    private final RefreshTokenConfig refreshTokenConfig = mock(RefreshTokenConfig.class);
    private final SessionService sut = new SessionServiceImpl(sessionServiceClient, refreshTokenConfig);

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
    public void Creating_session_is_successful() {
        String expectedUserID = create(String.class);
        RolesEnum[] expectedRoles = create(RolesEnum[].class);
        String[] expectedRolesNames =  Arrays.stream(expectedRoles).map(Enum::name).toArray(String[]::new);
        Instant expectedSessionCreatedAt = create(Instant.class);
        String expectedAccessToken = create(String.class);
        String expectedRefreshToken = create(String.class);
        String expectedTokenID = create(String.class);
        SessionCreationData expectedCreationData = new SessionCreationData(expectedUserID, expectedRoles);

        Session expectedSession = new Session(
                expectedUserID,
                expectedRolesNames,
                expectedSessionCreatedAt,
                expectedAccessToken,
                expectedRefreshToken,
                expectedTokenID
        );

        ResponseEntity<Session> expectedResponse = ResponseEntity.ok(expectedSession);

        when(sessionServiceClient.createSession(eq(expectedCreationData)))
                .thenReturn(expectedResponse);

        Session actualSession = sut.createSession(expectedCreationData);

        assertEquals(expectedSession, actualSession);

        verify(sessionServiceClient)
                .createSession(eq(expectedCreationData));
    }

    @ParameterizedTest
    @MethodSource("creatingSessionUnexpectedExceptions")
    public void Creating_session_with_unexpected_error_is_not_successful(
            Class<? extends FeignException> exceptionClass) {
        SessionCreationData expectedCreationData = create(SessionCreationData.class);

        when(sessionServiceClient.createSession(eq(expectedCreationData)))
                .thenThrow(exceptionClass);

        assertThrows(ServerErrorException.class, () -> sut.createSession(expectedCreationData));
    }

    private static List<Class<? extends FeignException>> creatingSessionUnexpectedExceptions() {
        return clientExceptions();
    }

    @Test
    public void Refreshing_session_with_valid_refresh_token_is_successful() {
        String expectedUserID = create(String.class);
        RolesEnum[] expectedRoles = create(RolesEnum[].class);
        String[] expectedRolesNames =  Arrays.stream(expectedRoles).map(Enum::name).toArray(String[]::new);
        Instant expectedSessionCreatedAt = create(Instant.class);
        String expectedAccessToken = create(String.class);
        String expectedOldRefreshToken = create(String.class);
        String expectedNewRefreshToken = create(String.class);
        String expectedTokenID = create(String.class);

        Session expectedSession = new Session(
                expectedUserID,
                expectedRolesNames,
                expectedSessionCreatedAt,
                expectedAccessToken,
                expectedNewRefreshToken,
                expectedTokenID
        );

        ResponseEntity<Session> expectedResponse = ResponseEntity.ok(expectedSession);
        RefreshSessionRequestBody expectedRequestBody = new RefreshSessionRequestBody(expectedOldRefreshToken);

        when(sessionServiceClient.refreshSession(eq(expectedRequestBody)))
                .thenReturn(expectedResponse);

        Session actualSession = sut.refreshSession(expectedOldRefreshToken);

        assertEquals(expectedSession, actualSession);

        verify(sessionServiceClient)
                .refreshSession(eq(expectedRequestBody));
    }

    @Test
    public void Refreshing_session_with_invalid_refresh_token_is_not_successful() {
        String expectedInvalidRefreshToken = create(String.class);
        RefreshSessionRequestBody expectedRequestBody = new RefreshSessionRequestBody(expectedInvalidRefreshToken);

        when(sessionServiceClient.refreshSession(eq(expectedRequestBody)))
                .thenThrow(FeignException.BadRequest.class);

        assertThrows(InvalidTokenException.class, () -> sut.refreshSession(expectedInvalidRefreshToken));
    }

    @ParameterizedTest
    @MethodSource("refreshingSessionUnexpectedExceptions")
    public void Refreshing_session_with_unexpected_exception_is_not_succesful(
            Class<? extends FeignException> exceptionClass) {
        RefreshSessionRequestBody expectedRequestBody = create(RefreshSessionRequestBody.class);

        when(sessionServiceClient.refreshSession(eq(expectedRequestBody)))
                .thenThrow(exceptionClass);

        assertThrows(ServerErrorException.class, () -> sut.refreshSession(expectedRequestBody.refreshToken()));
    }

    private static List<Class<? extends FeignException>> refreshingSessionUnexpectedExceptions() {
        return clientExceptions().stream()
                .filter(aClass -> ! aClass.equals(FeignException.BadRequest.class))
                .toList();
    }

    @Test
    public void Deleting_session_with_valid_refresh_token_is_successful() {
        String expectedRefreshToken = create(String.class);
        RefreshSessionRequestBody expectedRequestBody = new RefreshSessionRequestBody(expectedRefreshToken);

        sut.deleteSession(expectedRefreshToken);

        verify(sessionServiceClient)
                .deleteSession(eq(expectedRequestBody));
    }

    @Test
    public void Deleting_session_with_invalid_refresh_token_is_not_successful() {
        String expectedInvalidRefreshToken = create(String.class);
        RefreshSessionRequestBody expectedRequestBody = new RefreshSessionRequestBody(expectedInvalidRefreshToken);

        doThrow(FeignException.BadRequest.class)
            .when(sessionServiceClient).deleteSession(eq(expectedRequestBody));

        assertThrows(InvalidTokenException.class, () -> sut.deleteSession(expectedInvalidRefreshToken));
    }

    @ParameterizedTest
    @MethodSource("deletingSessionUnexpectedExceptions")
    public void Deleting_session_with_unexpected_exception_is_not_succesful(
            Class<? extends FeignException> exceptionClass) {
        RefreshSessionRequestBody expectedRequestBody = create(RefreshSessionRequestBody.class);

        when(sessionServiceClient.deleteSession(eq(expectedRequestBody)))
                .thenThrow(exceptionClass);

        assertThrows(ServerErrorException.class, () -> sut.deleteSession(expectedRequestBody.refreshToken()));
    }

    private static List<Class<? extends FeignException>> deletingSessionUnexpectedExceptions() {
        return clientExceptions().stream()
                .filter(aClass -> ! aClass.equals(FeignException.BadRequest.class))
                .toList();
    }

    private static List<Class<? extends FeignException>> clientExceptions() {
        return clientExceptions;
    }
}