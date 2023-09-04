package com.rednet.authmanagementservice.service;

import com.rednet.authmanagementservice.service.impl.SessionServiceClientFallbackFactory;
import com.rednet.authmanagementservice.entity.Session;
import com.rednet.authmanagementservice.payload.request.CreateSessionRequestBody;
import com.rednet.authmanagementservice.payload.request.RefreshSessionRequestBody;
import com.rednet.authmanagementservice.payload.response.SimpleResponseBody;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@FeignClient(name = "SESSION-SERVICE", fallbackFactory = SessionServiceClientFallbackFactory.class)
public interface SessionServiceClient {
    @PostMapping(path = "/sessions", consumes = APPLICATION_JSON_VALUE)
    ResponseEntity<Session> createSession(@RequestBody CreateSessionRequestBody requestBody);

    @GetMapping("/sessions/{session-id}")
    ResponseEntity<Session> getSession(@PathVariable("session-id") String sessionID);

    @GetMapping("/sessions")
    ResponseEntity<List<Session>> getSessionsByUserID(@RequestParam("user-id") String userID);

    @PutMapping(path = "/sessions", consumes = APPLICATION_JSON_VALUE)
    ResponseEntity<Session> refreshSession(@RequestBody RefreshSessionRequestBody requestBody);

    @PostMapping(path = "/session-removing-process", consumes = APPLICATION_JSON_VALUE)
    ResponseEntity<SimpleResponseBody> deleteSession(@RequestBody RefreshSessionRequestBody requestBody);

    @DeleteMapping("/sessions")
    ResponseEntity<SimpleResponseBody> deleteSessionsByUserID(@RequestParam("user-id") String userID);
}
