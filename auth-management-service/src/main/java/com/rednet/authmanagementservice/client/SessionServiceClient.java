package com.rednet.authmanagementservice.client;

import com.rednet.authmanagementservice.client.fallbackfactory.SessionServiceClientFallbackFactory;
import com.rednet.authmanagementservice.entity.Session;
import com.rednet.authmanagementservice.payload.request.CreateSessionRequestBody;
import com.rednet.authmanagementservice.payload.request.RefreshSessionRequestBody;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@FeignClient(
        name = "SESSION-SERVICE",
        path = "/sessions",
        fallbackFactory = SessionServiceClientFallbackFactory.class)
public interface SessionServiceClient {
    @PostMapping(
            consumes = APPLICATION_JSON_VALUE,
            produces = APPLICATION_JSON_VALUE)
    ResponseEntity<Session> createSession   (@RequestBody CreateSessionRequestBody requestBody);

    @PutMapping(
            consumes = APPLICATION_JSON_VALUE,
            produces = APPLICATION_JSON_VALUE)
    ResponseEntity<Session> refreshSession  (@RequestBody RefreshSessionRequestBody requestBody);

    @PostMapping(
            path = "/session-removing-process",
            consumes = APPLICATION_JSON_VALUE)
    ResponseEntity<Void>    deleteSession   (@RequestBody RefreshSessionRequestBody requestBody);
}
