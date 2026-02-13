package com.saathisquare.authservice.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.saathisquare.authservice.dto.request.LoginRequest;
import com.saathisquare.authservice.dto.request.SignupRequest;
import com.saathisquare.authservice.dto.request.UserDetailsRequest;
import com.saathisquare.authservice.dto.response.LoginResponse;
import com.saathisquare.authservice.dto.response.UserDetailsResponse;
import com.saathisquare.authservice.service.AuthService;
import com.saathisquare.authservice.util.Response;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api")
// CORS is handled by Gateway, @CrossOrigin not needed here
@RequiredArgsConstructor
public class AuthController {
	private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);

	private final AuthService authService;

	@PostMapping("/signup")
	public ResponseEntity<Response<String>> signup(@RequestBody SignupRequest request) {
		return ResponseEntity.status(HttpStatus.CREATED).body(authService.signup(request));
	}

	@PostMapping("/login")
	public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
		return ResponseEntity.ok(authService.login(request));
	}

	@PostMapping("/logout")
	public ResponseEntity<Void> logout(@RequestHeader("Authorization") String token) {
		authService.logout(token.substring(7)); // Remove Bearer
		return ResponseEntity.ok().build();
	}

	@PostMapping("/update-user-details")
	public ResponseEntity<Response<UserDetailsResponse>> updatePassword(@RequestBody UserDetailsRequest request) {
		LOGGER.info("Inside :: updatePassword : getting request is {}", request);
		return ResponseEntity.ok().body(authService.updateUserDetails(request));
	}
}
