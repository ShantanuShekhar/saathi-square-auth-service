package com.saathisquare.authservice.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import com.saathisquare.authservice.util.Constants;
import com.saathisquare.authservice.util.Response;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;

@ControllerAdvice
public class GlobalExceptionHandler {
	private static final Logger LOGGER = LoggerFactory.getLogger(GlobalExceptionHandler.class);

	@ExceptionHandler(Exception.class)
	public ResponseEntity<?> handleGeneral(Exception ex) {
		LOGGER.error("Inside : handleGeneral : {}", ex.getMessage(), ex);
		return ResponseEntity.status(500)
				.body(new Response<>(Constants.GLOBAL_ERROR_STATUS_CODE, Constants.GLOBAL_ERROR_MESSAGE, null));
	}

	@ExceptionHandler(BadCredentialsException.class)
	public ResponseEntity<?> handleBadCredentials(BadCredentialsException ex) {
		LOGGER.warn("Bad credentials: {}", ex.getMessage());
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
				.body(new Response<>(Constants.VALIDATION_ERROR_API_CODE, ex.getMessage(), null));
	}

	@ExceptionHandler(ExpiredJwtException.class)
	public ResponseEntity<?> handleExpiredJwtException(ExpiredJwtException ex) {
		LOGGER.warn("JWT token expired: {}", ex.getMessage());
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
				.body(new Response<>(Constants.VALIDATION_ERROR_API_CODE, "JWT token expired. Please login again.", null));
	}

	@ExceptionHandler({MalformedJwtException.class, UnsupportedJwtException.class, SignatureException.class})
	public ResponseEntity<?> handleJwtException(JwtException ex) {
		LOGGER.warn("Invalid JWT token: {}", ex.getMessage());
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
				.body(new Response<>(Constants.VALIDATION_ERROR_API_CODE, "Invalid JWT token.", null));
	}

}
