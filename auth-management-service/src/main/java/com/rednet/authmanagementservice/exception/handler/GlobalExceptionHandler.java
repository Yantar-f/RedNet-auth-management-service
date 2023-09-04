package com.rednet.authmanagementservice.exception.handler;

import com.rednet.authmanagementservice.exception.BadRequestException;
import com.rednet.authmanagementservice.exception.impl.ServerErrorException;
import com.rednet.authmanagementservice.payload.response.ErrorResponseBody;
import feign.FeignException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestCookieException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.text.DateFormat;
import java.util.Date;
import java.util.List;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private final DateFormat dateFormat;

    public GlobalExceptionHandler(DateFormat dateFormat) {
        this.dateFormat = dateFormat;
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ErrorResponseBody> handleBadRequest(
        BadRequestException ex,
        HttpServletRequest request
    ) {
        return generateBadRequest(request.getServletPath(), ex.getMessages());
    }

    @ExceptionHandler(ServerErrorException.class)
    public ResponseEntity<ErrorResponseBody> handleBadRequest(
        ServerErrorException ex,
        HttpServletRequest request
    ) {
        return generateServerError(request.getServletPath(), ex.getMessages());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponseBody> handleMethodArgumentNotValid(
        MethodArgumentNotValidException ex,
        HttpServletRequest request
    ) {
        return generateBadRequest(
            request.getServletPath(),
            ex.getBindingResult().getAllErrors().stream().map(ObjectError::getDefaultMessage).toList()
        );
    }

    @ExceptionHandler(MissingRequestCookieException.class)
    public ResponseEntity<ErrorResponseBody> handleMissingRequestCookie(
        MissingRequestCookieException ex,
        HttpServletRequest request
    ) {
        return generateBadRequest(request.getServletPath(), List.of(ex.getMessage()));
    }

    private ResponseEntity<ErrorResponseBody> generateServerError(String path, List<String> messages) {
        return ResponseEntity.internalServerError().body(
            new ErrorResponseBody(
                HttpStatus.INTERNAL_SERVER_ERROR.name(),
                dateFormat.format(new Date()),
                path,
                messages
            )
        );
    }

    private ResponseEntity<ErrorResponseBody> generateBadRequest(String path, List<String> errorMessages) {
        return ResponseEntity.badRequest().body(
            new ErrorResponseBody(
                HttpStatus.BAD_REQUEST.name(),
                dateFormat.format(new Date()),
                path,
                errorMessages
            )
        );
    }
}
