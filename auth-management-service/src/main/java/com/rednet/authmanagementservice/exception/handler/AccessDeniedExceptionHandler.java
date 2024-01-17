package com.rednet.authmanagementservice.exception.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rednet.authmanagementservice.exception.ErrorResponseBody;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;

@Component
public class AccessDeniedExceptionHandler implements AccessDeniedHandler {
    @Override
    public void handle(
        HttpServletRequest      request,
        HttpServletResponse     response,
        AccessDeniedException   accessDeniedException
    ) throws IOException, ServletException {
        HttpStatus status = HttpStatus.FORBIDDEN;

        response.setStatus(status.value());

        new ObjectMapper().writeValue(
            response.getOutputStream(),
            new ErrorResponseBody(
                status.name(),
                Instant.now(),
                request.getServletPath(),
                accessDeniedException.getMessage()
            )
        );
    }
}
