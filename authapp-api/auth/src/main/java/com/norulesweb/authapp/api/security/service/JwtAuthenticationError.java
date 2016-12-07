package com.norulesweb.authapp.api.security.service;

public class JwtAuthenticationError {

	private final String message;

	public JwtAuthenticationError(String message) { this.message = message; }

	public String getMessage() {
		return message;
	}
}
