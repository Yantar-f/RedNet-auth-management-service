package com.rednet.authmanagementservice.exception.handler;

import com.rednet.authmanagementservice.exception.ErrorResponseBody;
import com.rednet.authmanagementservice.exception.impl.InvalidAccountDataException;
import com.rednet.authmanagementservice.exception.impl.InvalidRegistrationDataException;
import com.rednet.authmanagementservice.exception.impl.InvalidTokenException;
import com.rednet.authmanagementservice.exception.impl.MissingTokenException;
import com.rednet.authmanagementservice.exception.impl.OccupiedValueException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.lang.NonNull;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.context.request.async.AsyncRequestTimeoutException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.time.Instant;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE;

@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {
    @Override
    protected ResponseEntity<Object> handleHttpRequestMethodNotSupported(
        @NonNull HttpRequestMethodNotSupportedException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request
    ) {
        return generateErrorResponse(BAD_REQUEST, extractPath(request), ex.getMessage());
    }

    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotSupported(
        @NonNull HttpMediaTypeNotSupportedException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request
    ) {
        return generateErrorResponse(BAD_REQUEST, extractPath(request), ex.getMessage());
    }

    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotAcceptable(
        @NonNull HttpMediaTypeNotAcceptableException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request
    ) {
        return generateErrorResponse(BAD_REQUEST, extractPath(request), ex.getMessage());
    }

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestParameter(
        @NonNull MissingServletRequestParameterException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request
    ) {
        return generateErrorResponse(BAD_REQUEST, extractPath(request), ex.getMessage());
    }

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestPart(
        @NonNull MissingServletRequestPartException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request
    ) {
        return generateErrorResponse(BAD_REQUEST, extractPath(request), ex.getMessage());
    }

    @Override
    protected ResponseEntity<Object> handleServletRequestBindingException(
        @NonNull ServletRequestBindingException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request
    ) {
        return generateErrorResponse(BAD_REQUEST, extractPath(request), ex.getMessage());
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
        @NonNull MethodArgumentNotValidException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request
    ) {
        FieldError fieldError = ex.getFieldError();
        String errorMessage = fieldError != null ? fieldError.getDefaultMessage() : "Undefined constraint violation";

        return generateErrorResponse(BAD_REQUEST, extractPath(request), errorMessage);
    }

    @Override
    protected ResponseEntity<Object> handleNoHandlerFoundException(
        @NonNull NoHandlerFoundException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request
    ) {
        return generateErrorResponse(NOT_FOUND, extractPath(request), ex.getMessage());
    }

    @Override
    protected ResponseEntity<Object> handleAsyncRequestTimeoutException(
        @NonNull AsyncRequestTimeoutException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request
    ) {
        return generateErrorResponse(SERVICE_UNAVAILABLE, extractPath(request), ex.getMessage());
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotWritable(
        @NonNull HttpMessageNotWritableException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request
    ) {
        return generateErrorResponse(INTERNAL_SERVER_ERROR, extractPath(request), ex.getMessage());
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(
        @NonNull HttpMessageNotReadableException ex,
        @NonNull HttpHeaders headers,
        @NonNull HttpStatusCode status,
        @NonNull WebRequest request
    ) {
        return generateErrorResponse(BAD_REQUEST, extractPath(request), ex.getMessage());
    }

    @ExceptionHandler(MissingTokenException.class)
    public ResponseEntity<Object> handleMissingTokenException(WebRequest request, MissingTokenException ex){
        return generateErrorResponse(BAD_REQUEST, extractPath(request), ex.getMessage());
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<Object> handleInvalidTokenException(WebRequest request, InvalidTokenException ex){
        return generateErrorResponse(BAD_REQUEST, extractPath(request), ex.getMessage());
    }

    @ExceptionHandler(OccupiedValueException.class)
    public ResponseEntity<Object> handleOccupiedValueException(WebRequest request, OccupiedValueException ex){
        return generateErrorResponse(BAD_REQUEST, extractPath(request), ex.getMessage());
    }

    @ExceptionHandler(InvalidAccountDataException.class)
    public ResponseEntity<Object> handleInvalidAccountDataException(WebRequest request, InvalidAccountDataException ex){
        return generateErrorResponse(BAD_REQUEST, extractPath(request), ex.getMessage());
    }

    @ExceptionHandler(InvalidRegistrationDataException.class)
    public ResponseEntity<Object> handleInvalidRegistrationData(WebRequest request, InvalidRegistrationDataException ex){
        return generateErrorResponse(BAD_REQUEST, extractPath(request), ex.getMessage());
    }

    private ResponseEntity<Object> generateErrorResponse(
        HttpStatus httpStatus,
        String path,
        String errorMessage
    ) {
        return ResponseEntity.status(httpStatus.value()).body(
            new ErrorResponseBody(
                httpStatus.name(),
                Instant.now(),
                path,
                errorMessage
            )
        );
    }

    private String extractPath(WebRequest request) {
        try {
            return ((ServletWebRequest) request).getRequest().getServletPath();
        } catch (ClassCastException ex) {
            return "/";
        }
    }
}
