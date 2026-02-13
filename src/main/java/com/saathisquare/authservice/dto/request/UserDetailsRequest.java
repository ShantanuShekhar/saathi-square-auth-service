package com.saathisquare.authservice.dto.request;

import java.util.UUID;

public record UserDetailsRequest(UUID id, String username, String email, String firstName, String lastName,
		String newPassword, String oldPassword, String roleName) {
	
	
}
