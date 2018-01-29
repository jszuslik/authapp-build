package com.norulesweb.authapp.api.security.controller;

import com.norulesweb.authapp.api.security.JwtTokenUtil;
import com.norulesweb.authapp.api.security.JwtUser;
import com.norulesweb.authapp.api.security.service.JwtAuthenticationError;
import com.norulesweb.authapp.api.security.service.JwtAuthenticationResponse;
import com.norulesweb.authapp.api.security.service.JwtUserDetailsServiceImpl;
import com.norulesweb.authapp.core.model.security.User;
import com.norulesweb.authapp.core.repository.security.UserRepository;
import com.norulesweb.authapp.core.service.request.DeleteRequest;
import com.norulesweb.authapp.core.service.request.RegistrationRequest;
import com.norulesweb.authapp.core.service.response.DeleteResponse;
import com.norulesweb.authapp.core.service.response.ErrorResponse;
import com.norulesweb.authapp.core.service.response.RegistrationResponse;
import com.norulesweb.authapp.core.service.security.UserDTO;
import com.norulesweb.authapp.core.service.security.UserService;
import com.norulesweb.authapp.core.utility.UserConstants;
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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
		if(SecurityContextHolder.getContext().getAuthentication().isAuthenticated()){
			String token = request.getHeader(this.tokenHeader);
			String username = jwtTokenUtil.getUsernameFromToken(token);
			String authResponse = "Authenticated User - " + username;

			final JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse(authResponse);
			logger.info("{} - Authenticated user - {}", getClass().toString(), username);

			return MessageBuilder.withPayload(jwtAuthenticationResponse).setHeader(STATUS_CODE, 200).build();
		}
		JwtAuthenticationError error = new JwtAuthenticationError(UserConstants.INVALID_USER_OR_PW);
		return MessageBuilder.withPayload(error).setHeader(STATUS_CODE, HttpServletResponse.SC_UNAUTHORIZED).build();
	}

	@Transformer
	public Message<?> refreshAndGetAuthenticationToken(){
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
		HttpServletResponse response = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getResponse();

		String token = request.getHeader(tokenHeader);
		String username = jwtTokenUtil.getUsernameFromToken(token);
		JwtUser user = userDetailsService.loadUserByUsername(username);
		if (null != user && jwtTokenUtil.canTokenBeRefreshed(token, user.getLastPasswordResetDate())) {
			String refreshedToken = jwtTokenUtil.refreshToken(token);
			response.setHeader(this.tokenHeader, refreshedToken);
			String authResponse = "Authenticated User - " + username;
			logger.info("{} - Authenticated user - {}", getClass().toString(), username);
			JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse(authResponse);
			return MessageBuilder.withPayload(jwtAuthenticationResponse).setHeader(STATUS_CODE, 200).build();
		} else {
			JwtAuthenticationError error = new JwtAuthenticationError(UserConstants.UNAUTHORIZED);
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
	@PreAuthorize("hasRole('ANONYMOUS')")
	public Message<?> registerFrontEndUser(Message<RegistrationRequest> regestrationRequestMessage) {
		HttpServletRequest httpRequest = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
		RegistrationRequest request = regestrationRequestMessage.getPayload();
		if(!checkMatchingPassword(request.getPassword(), request.getMatchingPassword()))
			return MessageBuilder.withPayload(new ErrorResponse("409", "Failure to register user")).setHeader(STATUS_CODE, 400).build();

		UserDTO newUserDTO = userService.createAppUser(registerRequestToUserDto(request));
		if(newUserDTO == null) {
			return MessageBuilder.withPayload(new ErrorResponse("409", "User with username already exists")).setHeader(STATUS_CODE, 409).build();
		}
		newUserDTO = addAuth(newUserDTO, UserConstants.FALSE);

		JwtUser user = userDetailsService.loadUserByUsername(newUserDTO.getUsername());

		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
		authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpRequest));
		logger.info("authenticated user " + user.getUsername() + ", setting security context");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		if(SecurityContextHolder.getContext().getAuthentication().isAuthenticated()){
			RegistrationResponse registrationResponse = new RegistrationResponse();
			registrationResponse.setToken(jwtTokenUtil.generateToken(user));
			registrationResponse.setUsername(user.getUsername());
			return MessageBuilder.withPayload(registrationResponse).setHeader(STATUS_CODE, 200).build();
		}
		return MessageBuilder.withPayload(new ErrorResponse("409", "Failure to register user")).setHeader(STATUS_CODE, 400).build();
	}

	@Transformer
	@PreAuthorize("hasRole('ADMIN')")
	public Message<?> registerNewUser(Message<RegistrationRequest> regestrationRequestMessage){
		RegistrationRequest request = regestrationRequestMessage.getPayload();
		if(!checkMatchingPassword(request.getPassword(), request.getMatchingPassword()))
			return MessageBuilder.withPayload("Failure to register user").setHeader(STATUS_CODE, 409).build();

		UserDTO newUserDTO = userService.createAppUser(registerRequestToUserDto(request));
		newUserDTO = addAuth(newUserDTO, request.getAdmin());

		JwtUser user = userDetailsService.loadUserByUsername(newUserDTO.getUsername());
		if(user != null){
			return MessageBuilder.withPayload(user).setHeader(STATUS_CODE, 200).build();
		}
		return MessageBuilder.withPayload("Failure to register user").setHeader(STATUS_CODE, 409).build();
	}

	@Transformer
	@PreAuthorize("hasRole('ADMIN')")
	public Message<?> deleteUser(Message<DeleteRequest> deleteRequestMessage){
		String username = deleteRequestMessage.getPayload().getUsername();
		User user = userRepository.findByUsername(username);
		if(user != null){
			userRepository.delete(user);
			user = userRepository.findByUsername(username);
			if(user == null){
				return MessageBuilder.withPayload(new DeleteResponse(username, UserConstants.DELETE_SUCCESS)).setHeader(STATUS_CODE, 200).build();
			} else {
				return MessageBuilder.withPayload(new DeleteResponse(username, UserConstants.DELETE_FAILED)).setHeader(STATUS_CODE, 405).build();
			}
		}
		return MessageBuilder.withPayload(new DeleteResponse(username, UserConstants.DELETE_FAILED)).setHeader(STATUS_CODE, 405).build();
	}

	@Transformer


	private Boolean checkMatchingPassword(String password, String matchingPassword){
		return password.equals(matchingPassword);
	}

	private UserDTO registerRequestToUserDto(RegistrationRequest regestrationRequest){
		UserDTO userDTO = new UserDTO();
		userDTO.setUsername(regestrationRequest.getUsername());
		userDTO.setPassword(regestrationRequest.getPassword());
		userDTO.setFirstname(regestrationRequest.getFirstName());
		userDTO.setLastname(regestrationRequest.getLastName());
		userDTO.setEmail(regestrationRequest.getEmail());
		userDTO.setEnabled(UserConstants.TRUE);

		return userDTO;
	}

	private UserDTO addAuth(UserDTO userDTO, Boolean isAdmin){
		if(isAdmin){
			userDTO = userService.addAdminAuth(userDTO);
			userDTO = userService.addUserAuth(userDTO);
		} else {
			userDTO = userService.addUserAuth(userDTO);
		}
		return userDTO;
	}

}
