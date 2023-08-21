package com.rednet.authmanagementservice.exception.handler;

import com.rednet.authmanagementservice.exception.BadRequestException;
import com.rednet.authmanagementservice.payload.response.ErrorResponseMessage;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.text.DateFormat;
import java.util.Date;
import java.util.List;

import static java.util.stream.Collectors.toList;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private final DateFormat dateFormat;

    public GlobalExceptionHandler(DateFormat dateFormat) {
        this.dateFormat = dateFormat;
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ErrorResponseMessage> handleBadRequest(
        BadRequestException ex,
        HttpServletRequest request
    ) {
        return generateBadRequest(request.getServletPath(), ex.getMessages());
    }

    @ExceptionHandler(value = MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponseMessage> handleMethodArgumentNotValid(
        MethodArgumentNotValidException ex,
        HttpServletRequest request
    ) {
        return generateBadRequest(
            request.getServletPath(),
            ex.getBindingResult().getAllErrors().stream().map(ObjectError::getDefaultMessage).toList()
        );
    }

    private ResponseEntity<ErrorResponseMessage> generateBadRequest(String path, List<String> errorMessages) {
        return ResponseEntity.badRequest().body(
            new ErrorResponseMessage(
                HttpStatus.BAD_REQUEST.name(),
                dateFormat.format(new Date()),
                path,
                errorMessages
            )
        );
    }
}
