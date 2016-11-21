package com.norulesweb.authapp.api.security.controller;

import com.norulesweb.authapp.api.security.JwtTokenUtil;
import com.norulesweb.authapp.api.security.JwtUser;
import com.norulesweb.authapp.api.security.service.JwtAuthenticationError;
import com.norulesweb.authapp.api.security.service.JwtAuthenticationResponse;
import com.norulesweb.authapp.api.security.service.JwtUserDetailsServiceImpl;
import com.norulesweb.authapp.core.model.security.User;
import com.norulesweb.authapp.core.repository.security.UserRepository;
import com.norulesweb.authapp.core.service.security.UserDTO;
import com.norulesweb.authapp.core.service.security.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.integration.annotation.MessageEndpoint;
import org.springframework.integration.annotation.Transformer;
import org.springframework.integration.support.MessageBuilder;
import org.springframework.messaging.Message;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;

import static org.springframework.integration.http.HttpHeaders.STATUS_CODE;

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

	@Value("${jwt.header.user}")
	private String headerUser;

	@Value("${jwt.header.password}")
	private String headerPassword;

	@Autowired
	protected UserService userService;

	@Transformer
	public Message<?> createAuthenticationToken() throws AuthenticationException {
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
		HttpServletResponse response = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getResponse();

		Collection<String> headerNames = response.getHeaderNames();
		for(String headerName : headerNames) {
			logger.info("{}", headerName);
		}

		String username = request.getHeader(this.headerUser);
		String password = request.getHeader(this.headerPassword);

		if(SecurityContextHolder.getContext().getAuthentication().isAuthenticated()){
			// Reload password post-security so we can generate token
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			JwtUser jwtUser = (JwtUser) authentication.getPrincipal();
			logger.info("Get Authentication - {}", jwtUser.getUsername());
			final UserDetails userDetails = userDetailsService.loadUserByUsername(jwtUser.getUsername());
			if (!BCrypt.checkpw(password, userDetails.getPassword())) {
				JwtAuthenticationError error = new JwtAuthenticationError("Invalid Password");
				return MessageBuilder.withPayload(error).setHeader(STATUS_CODE, 401).build();
			}
			if (!username.equals(userDetails.getUsername())){
				JwtAuthenticationError error = new JwtAuthenticationError("Invalid Username");
				return MessageBuilder.withPayload(error).setHeader(STATUS_CODE, 401).build();
			}
			final String token = jwtTokenUtil.generateToken(userDetails);
			final JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse(token);
			// Return the token
			return MessageBuilder.withPayload(jwtAuthenticationResponse).setHeader(STATUS_CODE, 200).build();
		}
		JwtAuthenticationError error = new JwtAuthenticationError("Invalid Credentials");
		return MessageBuilder.withPayload(error).setHeader(STATUS_CODE, 401).build();
	}
	@Transformer
	public Message<?> refreshAndGetAuthenticationToken(){
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();

		String token = request.getHeader(tokenHeader);
		String username = jwtTokenUtil.getUsernameFromToken(token);
		JwtUser user = userDetailsService.loadUserByUsername(username);

		if (jwtTokenUtil.canTokenBeRefreshed(token, user.getLastPasswordResetDate())) {
			String refreshedToken = jwtTokenUtil.refreshToken(token);
			JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse(refreshedToken);
			return MessageBuilder.withPayload(jwtAuthenticationResponse).setHeader(STATUS_CODE, 200).build();
		} else {
			JwtAuthenticationError error = new JwtAuthenticationError("Unauthorized");
			return MessageBuilder.withPayload(error).setHeader(STATUS_CODE, 401).build();
		}

	}
	@Transformer
	public Message<?> getAuthenticatedUser() {
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
		String token = request.getHeader(tokenHeader);
		String username = jwtTokenUtil.getUsernameFromToken(token);
		JwtUser user = userDetailsService.loadUserByUsername(username);
		return MessageBuilder.withPayload(user).setHeader(STATUS_CODE, 200).build();
	}

	@Transformer
	@PreAuthorize("hasRole('ADMIN')")
	public Message<?> registerNewUser(Message<UserDTO> userDTO){
		UserDTO newUserDTO = userService.createAppUser(userDTO.getPayload());
		newUserDTO = userService.addUserAuth(newUserDTO);
		JwtUser user = userDetailsService.loadUserByUsername(newUserDTO.getUsername());
		if(user != null){
			return MessageBuilder.withPayload(user).setHeader(STATUS_CODE, 200).build();
		}
		return MessageBuilder.withPayload("Failure to register user").setHeader(STATUS_CODE, 409).build();
	}

	@Transformer
	@PreAuthorize("hasRole('ADMIN')")
	public Message<?> deleteUser(Message<UserDTO> userDTO){
		User user = userRepository.findByUsername(userDTO.getPayload().getUsername());
		if(user != null){
			userRepository.delete(user);
			user = userRepository.findByUsername(userDTO.getPayload().getUsername());
			if(user == null){
				return MessageBuilder.withPayload("User Deleted").setHeader(STATUS_CODE, 200).build();
			} else {
				return MessageBuilder.withPayload("User Delete Failed").setHeader(STATUS_CODE, 405).build();
			}
		}
		return MessageBuilder.withPayload("User Delete Failed").setHeader(STATUS_CODE, 405).build();
	}

}
