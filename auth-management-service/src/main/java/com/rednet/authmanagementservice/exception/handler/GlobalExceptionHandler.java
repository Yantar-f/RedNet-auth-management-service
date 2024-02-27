package com.rednet.authmanagementservice.exception.handler;

import com.rednet.authmanagementservice.exception.InvalidAccountDataException;
import com.rednet.authmanagementservice.exception.InvalidRegistrationDataException;
import com.rednet.authmanagementservice.exception.InvalidTokenException;
import com.rednet.authmanagementservice.exception.MissingTokenException;
import com.rednet.authmanagementservice.exception.OccupiedValueException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
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
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.net.URI;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.NOT_ACCEPTABLE;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE;
import static org.springframework.http.HttpStatus.UNSUPPORTED_MEDIA_TYPE;
import static org.springframework.http.MediaType.APPLICATION_PROBLEM_JSON;

@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {
    @Override
    protected ResponseEntity<Object> handleHttpRequestMethodNotSupported(
            @NonNull HttpRequestMethodNotSupportedException ex,
            @NonNull HttpHeaders headers,
            @NonNull HttpStatusCode status,
            @NonNull WebRequest request) {
        return generateErrorResponse(
                BAD_REQUEST,
                extractURI(request),
                "Method not supported",
                ex.getMessage());
    }

    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotSupported(
            @NonNull HttpMediaTypeNotSupportedException ex,
            @NonNull HttpHeaders headers,
            @NonNull HttpStatusCode status,
            @NonNull WebRequest request) {
        return generateErrorResponse(
                UNSUPPORTED_MEDIA_TYPE,
                extractURI(request),
                "Media type not supported",
                ex.getMessage()
        );
    }

    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotAcceptable(
            @NonNull HttpMediaTypeNotAcceptableException ex,
            @NonNull HttpHeaders headers,
            @NonNull HttpStatusCode status,
            @NonNull WebRequest request) {
        return generateErrorResponse(
                NOT_ACCEPTABLE,
                extractURI(request),
                "Not acceptable media type",
                ex.getMessage()
        );
    }

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestParameter(
            @NonNull MissingServletRequestParameterException ex,
            @NonNull HttpHeaders headers,
            @NonNull HttpStatusCode status,
            @NonNull WebRequest request) {
        return generateErrorResponse(
                BAD_REQUEST,
                extractURI(request),
                "Missing request param",
                ex.getMessage()
        );
    }

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestPart(
            @NonNull MissingServletRequestPartException ex,
            @NonNull HttpHeaders headers,
            @NonNull HttpStatusCode status,
            @NonNull WebRequest request) {
        return generateErrorResponse(
                BAD_REQUEST,
                extractURI(request),
                "Missing request part",
                ex.getMessage()
        );
    }

    @Override
    protected ResponseEntity<Object> handleServletRequestBindingException(
            @NonNull ServletRequestBindingException ex,
            @NonNull HttpHeaders headers,
            @NonNull HttpStatusCode status,
            @NonNull WebRequest request) {
        return generateErrorResponse(
                BAD_REQUEST,
                extractURI(request),
                "Binding exception",
                ex.getMessage()
        );
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            @NonNull MethodArgumentNotValidException ex,
            @NonNull HttpHeaders headers,
            @NonNull HttpStatusCode status,
            @NonNull WebRequest request) {
        FieldError fieldError = ex.getBindingResult().getFieldError();
        String errorMessage = fieldError != null ? fieldError.getDefaultMessage() : "undefined constraint violation";

        return generateErrorResponse(
                BAD_REQUEST,
                extractURI(request),
                "Argument nor valid",
                errorMessage
        );
    }

    @Override
    protected ResponseEntity<Object> handleNoHandlerFoundException(
            @NonNull NoHandlerFoundException ex,
            @NonNull HttpHeaders headers,
            @NonNull HttpStatusCode status,
            @NonNull WebRequest request) {
        return generateErrorResponse(
                NOT_FOUND,
                extractURI(request),
                "No handler found",
                ex.getMessage()
        );
    }

    @Override
    protected ResponseEntity<Object> handleAsyncRequestTimeoutException(
            @NonNull AsyncRequestTimeoutException ex,
            @NonNull HttpHeaders headers,
            @NonNull HttpStatusCode status,
            @NonNull WebRequest request) {
        return generateErrorResponse(
                SERVICE_UNAVAILABLE,
                extractURI(request),
                "Request timeout",
                ex.getMessage()
        );
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotWritable(
            @NonNull HttpMessageNotWritableException ex,
            @NonNull HttpHeaders headers,
            @NonNull HttpStatusCode status,
            @NonNull WebRequest request) {
        return generateErrorResponse(
                INTERNAL_SERVER_ERROR,
                extractURI(request),
                "Not writable http message",
                ex.getMessage()
        );
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(
            @NonNull HttpMessageNotReadableException ex,
            @NonNull HttpHeaders headers,
            @NonNull HttpStatusCode status,
            @NonNull WebRequest request) {
        return generateErrorResponse(
                BAD_REQUEST,
                extractURI(request),
                "Not readable http message",
                ex.getMessage()
        );
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    protected ResponseEntity<Object> handleMethodArgumentTypeMismatch(MethodArgumentTypeMismatchException ex,
                                                                      WebRequest request) {
        return generateErrorResponse(
                BAD_REQUEST,
                extractURI(request),
                "Argument type mismatch",
                ex.getMessage()
        );
    }

    @ExceptionHandler(MissingTokenException.class)
    public ResponseEntity<Object> handleMissingTokenException(WebRequest request, MissingTokenException ex){
        return generateErrorResponse(
                BAD_REQUEST,
                extractURI(request),
                "Missing token",
                ex.getMessage()
        );
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<Object> handleInvalidTokenException(WebRequest request, InvalidTokenException ex){
        return generateErrorResponse(
                BAD_REQUEST,
                extractURI(request),
                "Invalid token",
                ex.getMessage()
        );
    }

    @ExceptionHandler(OccupiedValueException.class)
    public ResponseEntity<Object> handleOccupiedValueException(WebRequest request, OccupiedValueException ex){
        return generateErrorResponse(
                CONFLICT,
                extractURI(request),
                "Occupied value",
                ex.getMessage()
        );
    }

    @ExceptionHandler(InvalidAccountDataException.class)
    public ResponseEntity<Object> handleInvalidAccountDataException(WebRequest request,
                                                                    InvalidAccountDataException ex) {
        return generateErrorResponse(
                BAD_REQUEST,
                extractURI(request),
                "Invalid account data"
                ,ex.getMessage()
        );
    }

    @ExceptionHandler(InvalidRegistrationDataException.class)
    public ResponseEntity<Object> handleInvalidRegistrationData(WebRequest request,
                                                                InvalidRegistrationDataException ex) {
        return generateErrorResponse(
                BAD_REQUEST,
                extractURI(request),
                "Invalid registration data",
                ex.getMessage()
        );
    }

    private ResponseEntity<Object> generateErrorResponse(HttpStatus httpStatus,
                                                         String requestUri,
                                                         String errorTitle,
                                                         String errorMessage) {

        ProblemDetail body = ProblemDetail.forStatus(httpStatus.value());

        body.setDetail(errorMessage);
        body.setInstance(URI.create(requestUri));
        body.setTitle(errorTitle);

        return ResponseEntity
                .status(httpStatus.value())
                .contentType(APPLICATION_PROBLEM_JSON)
                .body(body);
    }

    private String extractURI(WebRequest request) {
        try {
            return ((ServletWebRequest) request).getRequest().getServletPath();
        } catch (ClassCastException ex) {
            return "/";
        }
    }
}
