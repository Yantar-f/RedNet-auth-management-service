package com.rednet.authmanagementservice.client.fallbackfactory;

import com.rednet.authmanagementservice.entity.Session;
import com.rednet.authmanagementservice.exception.ServerErrorException;
import com.rednet.authmanagementservice.model.SessionCreationData;
import com.rednet.authmanagementservice.payload.request.RefreshSessionRequestBody;
import com.rednet.authmanagementservice.client.SessionServiceClient;
import feign.FeignException;
import org.springframework.cloud.openfeign.FallbackFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@Component
public class SessionServiceClientFallbackFactory implements FallbackFactory<SessionServiceClient> {
    @Override
    public SessionServiceClient create(Throwable cause) {
        return new SessionServiceClient() {
            @Override
            public ResponseEntity<Session> createSession(SessionCreationData requestBody) {
                throw new ServerErrorException("error during creating session");
            }

            @Override
            public ResponseEntity<Session> refreshSession(RefreshSessionRequestBody requestBody) {
                if (cause instanceof FeignException.BadRequest exception) {
                    throw exception;
                } else {
                    throw new ServerErrorException("error during refreshing session");
                }
            }

            @Override
            public ResponseEntity<Void> deleteSession(RefreshSessionRequestBody requestBody) {
                if (cause instanceof FeignException.BadRequest exception) {
                    throw exception;
                } else {
                    throw new ServerErrorException("error during deleting session");
                }
            }
        };
    }
}
