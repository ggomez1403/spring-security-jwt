package org.adaschool.api.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class CustomExceptionHandler {

    @ExceptionHandler(ServerErrorException.class)
    public ResponseEntity<ErrorResponse> handleCustomException(ServerErrorException ex) {
        ErrorResponse errorResponse = new ErrorResponse(ex.getMessage());
        ex.printStackTrace();
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGlobalException(Exception ex) {
        ex.printStackTrace();
        String errorMessage = "An unexpected error occurred";
        HttpStatus httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;
        if (ex instanceof ServerErrorException) {
            return handleCustomException((ServerErrorException) ex);
        } else if (ex instanceof AccessDeniedException) {
            errorMessage = "The user cannot perform the requested operation";
            httpStatus = HttpStatus.UNAUTHORIZED;
        }
        return new ResponseEntity<>(new ErrorResponse(errorMessage), httpStatus);
    }
}
