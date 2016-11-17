package com.norulesweb.authapp.api.security.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface JwtUserDetailsService extends UserDetailsService {

	@Override
	UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;

}
