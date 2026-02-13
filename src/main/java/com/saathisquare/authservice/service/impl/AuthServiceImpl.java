package com.saathisquare.authservice.service.impl;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.saathisquare.authservice.client.RbacClient;
import com.saathisquare.authservice.dto.request.LoginRequest;
import com.saathisquare.authservice.dto.request.SignupRequest;
import com.saathisquare.authservice.dto.request.UserDetailsRequest;
import com.saathisquare.authservice.dto.response.LoginResponse;
import com.saathisquare.authservice.dto.response.UserDetailsResponse;
import com.saathisquare.authservice.model.AuthToken;
import com.saathisquare.authservice.model.AuthToken.TokenStatus;
import com.saathisquare.authservice.service.AuthService;
import com.saathisquare.authservice.service.AuthTokenService;
import com.saathisquare.authservice.service.JwtService;
import com.saathisquare.authservice.util.Response;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
	private static final Logger LOGGER = LoggerFactory.getLogger(AuthServiceImpl.class);

	@Value("${jwt.expiration-ms:86400000}") // Default to 24 hours
	private long expirationMs;

	@Value("${jwt.secret}")
	private String secret;

	private final RbacClient rbacClient;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final AuthTokenService authTokenService;

	@Override
	public LoginResponse login(LoginRequest request) {
		LOGGER.info("Inside : login : {}", request);
		var response = rbacClient.getLoginDetailsByUsername(request.username());
		LOGGER.info("getting response : {}", response);
		UserDetailsResponse user = response.getBody().getData();

		LOGGER.info("getting user details is {}", user);
		LOGGER.info("getting user password is {}", user.getPassword());

		if (user == null || user.getPassword() == null
				|| !passwordEncoder.matches(request.password(), user.getPassword())) {

			LOGGER.info("password is incorrect");
			throw new BadCredentialsException("Invalid credentials");
		}
		LOGGER.info("password is incorrect");

		// Create Spring Security UserDetails
		UserDetails userDetails = User.withUsername(user.getUsername()).password(user.getPassword())
				.authorities(user.getRoleName()).build();

		String token = jwtService.generateToken(userDetails);
		AuthToken authToken = AuthToken.builder().userId(user.getId()).token(token).status(TokenStatus.ACTIVE)
				.issuedAt(Instant.now()).expiresAt(Instant.now().plusMillis(jwtService.getExpirationMs())).build();
		authTokenService.create(authToken);
		return new LoginResponse(token, user.getUsername(), user.getRoleName());
	}

	@Override
	public void logout(String token) {
		AuthToken existingToken = authTokenService.findByToken(token);

		existingToken.setStatus(TokenStatus.REVOKED);
		existingToken.setRevokedAt(Instant.now());
		authTokenService.create(existingToken);
	}

	@Override
	public Response<String> signup(SignupRequest request) {
		ResponseEntity<Response<String>> response = rbacClient.createUser(request);
		return response.getBody();
	}

	@Override
	public Response<UserDetailsResponse> updateUserDetails(UserDetailsRequest request) {
		LOGGER.info("Inside updateUserDetails: email={}, hasOldPassword={}, hasNewPassword={}", 
				request.email(), 
				request.oldPassword() != null && !request.oldPassword().isEmpty(),
				request.newPassword() != null && !request.newPassword().isEmpty());
		
		// Fetch user to get ID and validate password if changing password
		var userResponse = rbacClient.getLoginDetailsByUsername(request.email()).getBody().getData();

		// Only validate old password if trying to change password (newPassword is provided)
		if (request.newPassword() != null && !request.newPassword().isEmpty()) {
			if (request.oldPassword() == null || request.oldPassword().isEmpty()) {
				throw new BadCredentialsException("Old password is required when changing password");
			}
			if (!passwordEncoder.matches(request.oldPassword(), userResponse.getPassword())) {
				throw new BadCredentialsException("Old password doesn't match");
			}
		}
		
		// Validate that we have the user ID
		if (userResponse.getId() == null) {
			LOGGER.error("User ID is null for email: {}", request.email());
			throw new IllegalStateException("Unable to retrieve user ID for email: " + request.email());
		}
		
		// Create update request with user ID from fetched user
		// This ensures the RBAC service can find the user by ID (more reliable than email lookup)
		var updateRequest = new UserDetailsRequest(
				userResponse.getId(), // UUID from fetched user - required for update
				request.username() != null && !request.username().isEmpty() ? request.username() : userResponse.getUsername(),
				request.email() != null && !request.email().isEmpty() ? request.email() : userResponse.getEmail(),
				request.firstName(),
				request.lastName(),
				request.newPassword(),
				request.oldPassword(),
				request.roleName()
		);
		
		LOGGER.info("Sending update request with ID: {}, email: {}", updateRequest.id(), updateRequest.email());
		return rbacClient.updateUser(updateRequest).getBody();
	}
}
