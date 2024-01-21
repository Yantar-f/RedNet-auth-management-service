package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.client.SessionServiceClient;
import com.rednet.authmanagementservice.config.RefreshTokenConfig;
import com.rednet.authmanagementservice.config.RolesEnum;
import com.rednet.authmanagementservice.entity.Session;
import com.rednet.authmanagementservice.exception.InvalidTokenException;
import com.rednet.authmanagementservice.model.SessionCreationData;
import com.rednet.authmanagementservice.payload.request.RefreshSessionRequestBody;
import com.rednet.authmanagementservice.service.SessionService;
import feign.FeignException;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.Arrays;

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

    @Test
    public void Creating_session_is_always_successful() {
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
}