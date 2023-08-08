package com.rednet.authmanagementservice.exception.handler;

import com.rednet.authmanagementservice.exception.InvalidAccountDataException;
import com.rednet.authmanagementservice.exception.OccupiedValueException;
import com.rednet.authmanagementservice.payload.ErrorResponseMessage;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private final DateFormat dateFormat;

    public GlobalExceptionHandler(DateFormat dateFormat) {
        this.dateFormat = dateFormat;
    }

    @ExceptionHandler(OccupiedValueException.class)
    public ResponseEntity<ErrorResponseMessage> handleOccupiedValue(
        OccupiedValueException ex,
        HttpServletRequest request
    ) {
        return ResponseEntity.badRequest().body(
            new ErrorResponseMessage(
                HttpStatus.BAD_REQUEST.name(),
                dateFormat.format(new Date()),
                request.getRequestURI(),
                new ArrayList<>(){{add(ex.getMessage());}}
            )
        );
    }

    @ExceptionHandler(InvalidAccountDataException.class)
    public ResponseEntity<ErrorResponseMessage> handleInvalidAccountData(
        InvalidAccountDataException ex,
        HttpServletRequest request
    ) {
        return ResponseEntity.badRequest().body(
            new ErrorResponseMessage(
                HttpStatus.BAD_REQUEST.name(),
                dateFormat.format(new Date()),
                request.getRequestURI(),
                new ArrayList<>(){{add(ex.getMessage());}}
            )
        );
    }
}
