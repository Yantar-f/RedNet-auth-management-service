package com.rednet.authmanagementservice.exception.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rednet.authmanagementservice.payload.ErrorResponseMessage;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;

@Component
public class AuthenticationExceptionHandler implements AuthenticationEntryPoint {
    private final DateFormat dateFormat;

    @Autowired
    AuthenticationExceptionHandler(DateFormat dateFormat) {
        this.dateFormat = dateFormat;
    }

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
            new ErrorResponseMessage(
                status.name(),
                dateFormat.format(new Date()),
                request.getServletPath(),
                new ArrayList<>(){{add("Api authorization is required");}}
            )
        );
    }
}
