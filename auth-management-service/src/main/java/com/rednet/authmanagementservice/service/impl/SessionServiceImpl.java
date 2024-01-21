package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.config.RefreshTokenConfig;
import com.rednet.authmanagementservice.entity.Session;
import com.rednet.authmanagementservice.exception.InvalidTokenException;
import com.rednet.authmanagementservice.exception.ServerErrorException;
import com.rednet.authmanagementservice.model.SessionCreationData;
import com.rednet.authmanagementservice.payload.request.RefreshSessionRequestBody;
import com.rednet.authmanagementservice.service.SessionService;
import com.rednet.authmanagementservice.client.SessionServiceClient;
import feign.FeignException;
import org.springframework.stereotype.Service;

import java.util.Optional;


@Service
public class SessionServiceImpl implements SessionService {
    private final SessionServiceClient serviceClient;
    private final RefreshTokenConfig refreshTokenConfig;

    public SessionServiceImpl(SessionServiceClient serviceClient, RefreshTokenConfig refreshTokenConfig) {
        this.serviceClient = serviceClient;
        this.refreshTokenConfig = refreshTokenConfig;
    }

    @Override
    public Session createSession(SessionCreationData creationData) {
        Session session = serviceClient
                .createSession(new SessionCreationData(creationData.userID(), creationData.roles()))
                .getBody();

        return Optional
                .ofNullable(session)
                .orElseThrow(() -> new ServerErrorException("Error during creating session"));
    }

    @Override
    public Session refreshSession(String refreshToken) {
        try {
            Session session = serviceClient.refreshSession(new RefreshSessionRequestBody(refreshToken)).getBody();
            return Optional
                    .ofNullable(session)
                    .orElseThrow(() -> new ServerErrorException("Error during updating session"));
        } catch (FeignException.BadRequest exception) {
            throw new InvalidTokenException(refreshTokenConfig);
        }
    }

    @Override
    public void deleteSession(String refreshToken) {
        try {
            serviceClient.deleteSession(new RefreshSessionRequestBody(refreshToken));
        } catch (FeignException.BadRequest exception) {
            throw new InvalidTokenException(refreshTokenConfig);
        }
    }
}
