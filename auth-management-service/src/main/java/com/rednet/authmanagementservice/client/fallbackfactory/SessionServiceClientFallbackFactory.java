package com.rednet.authmanagementservice.client.fallbackfactory;

import com.rednet.authmanagementservice.entity.Session;
import com.rednet.authmanagementservice.exception.InvalidTokenException;
import com.rednet.authmanagementservice.exception.ServerErrorException;
import com.rednet.authmanagementservice.payload.request.CreateSessionRequestBody;
import com.rednet.authmanagementservice.payload.request.RefreshSessionRequestBody;
import com.rednet.authmanagementservice.client.SessionServiceClient;
import feign.FeignException;
import org.springframework.cloud.openfeign.FallbackFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

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
            public ResponseEntity<Session> refreshSession(RefreshSessionRequestBody requestBody) {
                if (cause instanceof FeignException.BadRequest) {
                    throw new InvalidTokenException(REFRESH_TOKEN);
                } else {
                    throw new ServerErrorException("error during refreshing session");
                }
            }

            @Override
            public ResponseEntity<Void> deleteSession(RefreshSessionRequestBody requestBody) {
                if (cause instanceof FeignException.BadRequest) {
                    throw new InvalidTokenException(REFRESH_TOKEN);
                } else {
                    throw new ServerErrorException("error during deleting session");
                }
            }
        };
    }
}
