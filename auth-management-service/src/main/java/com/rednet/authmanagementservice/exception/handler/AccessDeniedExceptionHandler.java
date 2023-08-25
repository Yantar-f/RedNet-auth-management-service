package com.rednet.authmanagementservice.exception.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rednet.authmanagementservice.payload.response.ErrorResponseBody;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;

@Component
public class AccessDeniedExceptionHandler implements AccessDeniedHandler {
    private final DateFormat dateFormat;

    @Autowired
    AccessDeniedExceptionHandler(DateFormat dateFormat) {
        this.dateFormat = dateFormat;
    }

    @Override
    public void handle(
        HttpServletRequest request,
        HttpServletResponse response,
        AccessDeniedException accessDeniedException
    ) throws IOException, ServletException {
        HttpStatus status = HttpStatus.FORBIDDEN;

        response.setStatus(status.value());

        new ObjectMapper().writeValue(
            response.getOutputStream(),
            new ErrorResponseBody(
                status.name(),
                dateFormat.format(new Date()),
                request.getServletPath(),
                new ArrayList<>(){{add(accessDeniedException.getMessage());}}
            )
        );
    }
}
