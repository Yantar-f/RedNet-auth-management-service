package com.rednet.authmanagementservice.exception.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rednet.authmanagementservice.exception.ErrorResponseBody;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;

@Component
public class AuthenticationExceptionHandler implements AuthenticationEntryPoint {
    @Override
    public void commence(
        HttpServletRequest request,
        HttpServletResponse response,
        AuthenticationException authException
    ) throws IOException, ServletException {
        HttpStatus status = HttpStatus.UNAUTHORIZED;

        response.setStatus(status.value());

        new ObjectMapper().writeValue(
            response.getOutputStream(),
            new ErrorResponseBody(
                status.name(),
                Instant.now(),
                request.getServletPath(),
                "Api authorization is required"
            )
        );
    }
}
