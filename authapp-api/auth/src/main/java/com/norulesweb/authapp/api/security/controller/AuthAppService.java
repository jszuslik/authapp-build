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

		String username = request.getHeader(this.headerUser);
		String password = request.getHeader(this.headerPassword);

		if(SecurityContextHolder.getContext().getAuthentication().isAuthenticated()){
			// Reload password post-security so we can generate token
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			JwtUser jwtUser = (JwtUser) authentication.getPrincipal();
			logger.info("Get Authentication - {}", jwtUser.getUsername());
			final UserDetails userDetails = userDetailsService.loadUserByUsername(jwtUser.getUsername());
			if (!BCrypt.checkpw(password, userDetails.getPassword())) {
				JwtAuthenticationError error = new JwtAuthenticationError(UserConstants.INVALID_PASSWORD);
				return MessageBuilder.withPayload(error).setHeader(STATUS_CODE, 401).build();
			}
			if (!username.equals(userDetails.getUsername())){
				JwtAuthenticationError error = new JwtAuthenticationError(UserConstants.INVALID_USERNAME);
				return MessageBuilder.withPayload(error).setHeader(STATUS_CODE, 401).build();
			}
			final String token = jwtTokenUtil.generateToken(userDetails);
			final JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse(token);
			// Return the token
			return MessageBuilder.withPayload(jwtAuthenticationResponse).setHeader(STATUS_CODE, 200).build();
		}
		JwtAuthenticationError error = new JwtAuthenticationError(UserConstants.INVALID_USER_OR_PW);
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
			return MessageBuilder.withPayload("Failure to register user").setHeader(STATUS_CODE, 409).build();

		UserDTO newUserDTO = userService.createAppUser(registerRequestToUserDto(request));
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
		return MessageBuilder.withPayload("Failure to register user").setHeader(STATUS_CODE, 409).build();
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
