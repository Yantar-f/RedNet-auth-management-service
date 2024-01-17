package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.config.EnumRoles;
import com.rednet.authmanagementservice.entity.Session;
import com.rednet.authmanagementservice.payload.request.CreateSessionRequestBody;
import com.rednet.authmanagementservice.payload.request.RefreshSessionRequestBody;
import com.rednet.authmanagementservice.service.SessionService;
import com.rednet.authmanagementservice.client.SessionServiceClient;
import org.springframework.stereotype.Service;

@Service
public class SessionServiceImpl implements SessionService {
    private final SessionServiceClient serviceClient;

    public SessionServiceImpl(SessionServiceClient serviceClient) {
        this.serviceClient = serviceClient;
    }

    @Override
    public Session createSession(String userID, EnumRoles[] roles) {
        return serviceClient.createSession(new CreateSessionRequestBody(userID, roles)).getBody();
    }

    @Override
    public Session refreshSession(String refreshToken) {
        return serviceClient.refreshSession(new RefreshSessionRequestBody(refreshToken)).getBody();
    }

    @Override
    public void deleteSession(String refreshToken) {
        serviceClient.deleteSession(new RefreshSessionRequestBody(refreshToken));
    }
}
