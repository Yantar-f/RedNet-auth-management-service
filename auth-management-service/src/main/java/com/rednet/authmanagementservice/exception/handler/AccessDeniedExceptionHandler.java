package com.rednet.authmanagementservice.exception.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;

@Component
public class AccessDeniedExceptionHandler implements AccessDeniedHandler {
    private final ObjectMapper objectMapper;

    public AccessDeniedExceptionHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {
        HttpStatus status = HttpStatus.FORBIDDEN;
        ProblemDetail body = ProblemDetail.forStatus(status.value());

        response.setStatus(status.value());

        body.setTitle(status.name());
        body.setDetail(accessDeniedException.getMessage());
        body.setInstance(URI.create(request.getRequestURI()));

        objectMapper.writeValue(response.getOutputStream(), body);
    }
}
