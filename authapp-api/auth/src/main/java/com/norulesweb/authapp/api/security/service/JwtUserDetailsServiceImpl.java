package com.norulesweb.authapp.api.security.service;

import com.norulesweb.authapp.api.security.JwtUser;
import com.norulesweb.authapp.api.security.JwtUserFactory;
import com.norulesweb.authapp.core.model.security.User;
import com.norulesweb.authapp.core.repository.security.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class JwtUserDetailsServiceImpl implements JwtUserDetailsService {

	private static final Logger logger = LoggerFactory.getLogger(JwtUserDetailsServiceImpl.class);

	@Autowired
	private UserRepository userRepository;

	@Override
	public JwtUser loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepository.findByUsername(username);
		logger.info("Found User- {}", user.getUsername());
		if (user == null) {
			throw new UsernameNotFoundException(String.format("No user found with username '%s'.", username));
		} else {
			return JwtUserFactory.create(user);
		}
	}
}
