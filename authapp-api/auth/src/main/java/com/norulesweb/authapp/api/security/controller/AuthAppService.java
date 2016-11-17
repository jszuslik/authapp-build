package com.norulesweb.authapp.api.security.controller;

import com.norulesweb.authapp.api.security.JwtAuthenticationRequest;
import com.norulesweb.authapp.api.security.JwtTokenUtil;
import com.norulesweb.authapp.api.security.JwtUser;
import com.norulesweb.authapp.api.security.service.JwtAuthenticationResponse;
import com.norulesweb.authapp.api.security.service.JwtUserDetailsServiceImpl;
import com.norulesweb.authapp.core.repository.security.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.integration.annotation.MessageEndpoint;
import org.springframework.integration.annotation.Transformer;
import org.springframework.messaging.Message;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;

@Component
@MessageEndpoint
public class AuthAppService {

	private static final Logger logger = LoggerFactory.getLogger(JwtUserDetailsServiceImpl.class);

	@Value("${jwt.header}")
	protected String tokenHeader;

	@Autowired
	protected AuthenticationManager authenticationManager;

	@Autowired
	protected JwtTokenUtil jwtTokenUtil;

	@Autowired
	protected JwtUserDetailsServiceImpl userDetailsService;

	@Autowired
	protected UserRepository userRepository;

	@Transformer
	public ResponseEntity<?> createAuthenticationToken(Message<JwtAuthenticationRequest> authenticationRequest) throws AuthenticationException {
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();

		String username = authenticationRequest.getPayload().getUsername();
		String password = authenticationRequest.getPayload().getPassword();

		JwtUser user = userDetailsService.loadUserByUsername(username);

		if(null == user || (! BCrypt.checkpw(password, user.getPassword()))) {
			throw new BadCredentialsException("Invalid username or password");
		}
		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
		authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
		logger.info("authenticated user " + username + ", setting security context");
		SecurityContextHolder.getContext().setAuthentication(authentication);

		// Reload password post-security so we can generate token
		final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getPayload().getUsername());
		final String token = jwtTokenUtil.generateToken(userDetails);

		// Return the token
		return ResponseEntity.ok(new JwtAuthenticationResponse(token));
	}
	@Transformer
	public ResponseEntity<?> refreshAndGetAuthenticationToken(){
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();

		String token = request.getHeader(tokenHeader);
		String username = jwtTokenUtil.getUsernameFromToken(token);
		JwtUser user = userDetailsService.loadUserByUsername(username);

		if (jwtTokenUtil.canTokenBeRefreshed(token, user.getLastPasswordResetDate())) {
			String refreshedToken = jwtTokenUtil.refreshToken(token);
			return ResponseEntity.ok(new JwtAuthenticationResponse(refreshedToken));
		} else {
			return ResponseEntity.badRequest().body(null);
		}

	}
	@Transformer
	public JwtUser getAuthenticatedUser() {
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
		String token = request.getHeader(tokenHeader);
		String username = jwtTokenUtil.getUsernameFromToken(token);
		JwtUser user = userDetailsService.loadUserByUsername(username);
		return user;
	}

	@Transformer
	public ResponseEntity<?> getProtectedGreeting(){
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
		return ResponseEntity.ok("Greetings from admin protected method!");
	}

}
