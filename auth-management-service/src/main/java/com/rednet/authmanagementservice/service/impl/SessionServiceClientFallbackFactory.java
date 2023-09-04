package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.entity.Session;
import com.rednet.authmanagementservice.exception.impl.InvalidTokenException;
import com.rednet.authmanagementservice.exception.impl.ServerErrorException;
import com.rednet.authmanagementservice.exception.impl.SessionNotFoundException;
import com.rednet.authmanagementservice.exception.impl.UserSessionsNotFoundException;
import com.rednet.authmanagementservice.payload.request.CreateSessionRequestBody;
import com.rednet.authmanagementservice.payload.request.RefreshSessionRequestBody;
import com.rednet.authmanagementservice.payload.response.SimpleResponseBody;
import com.rednet.authmanagementservice.service.SessionServiceClient;
import feign.FeignException;
import org.springframework.cloud.openfeign.FallbackFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.util.List;

import static com.rednet.authmanagementservice.config.EnumTokenType.REFRESH_TOKEN;

@Component
public class SessionServiceClientFallbackFactory implements FallbackFactory<SessionServiceClient> {
    @Override
    public SessionServiceClient create(Throwable cause) {
        return new SessionServiceClient() {
            @Override
            public ResponseEntity<Session> createSession(CreateSessionRequestBody requestBody) {
                throw new ServerErrorException("error during creating session");
            }

            @Override
            public ResponseEntity<Session> getSession(String sessionID) {
                if (cause instanceof FeignException.NotFound) {
                    throw new SessionNotFoundException(sessionID);
                } else {
                    throw new ServerErrorException("error during receiving session");
                }
            }

            @Override
            public ResponseEntity<List<Session>> getSessionsByUserID(String userID) {
                if (cause instanceof FeignException.NotFound) {
                    throw new UserSessionsNotFoundException(userID);
                } else {
                    throw new ServerErrorException("error during receiving sessions");
                }
            }

            @Override
            public ResponseEntity<Session> refreshSession(RefreshSessionRequestBody requestBody) {
                if (cause instanceof FeignException.NotFound) {
                    throw new InvalidTokenException(REFRESH_TOKEN);
                } else {
                    throw new ServerErrorException("error during refreshing session");
                }
            }

            @Override
            public ResponseEntity<SimpleResponseBody> deleteSession(RefreshSessionRequestBody requestBody) {
                if (cause instanceof FeignException.NotFound) {
                    throw new InvalidTokenException(REFRESH_TOKEN);
                } else {
                    throw new ServerErrorException("error during deleting session");
                }
            }

            @Override
            public ResponseEntity<SimpleResponseBody> deleteSessionsByUserID(String userID) {
                if (cause instanceof FeignException.NotFound) {
                    throw new UserSessionsNotFoundException(userID);
                } else {
                    throw new ServerErrorException("error during deleting sessions");
                }
            }
        };
    }
}
