package com.norulesweb.authapp.core.service.user;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class UserLookupImpl implements UserLookup {

	@Override
	public UserDetails getCurrentUser() {
		UserDetails returnUser = null;

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if(auth != null) {
			UserDetails userDetails = (UserDetails) auth.getPrincipal();
			if(userDetails != null){
				returnUser = userDetails;
			}
		}
		return returnUser;
	}
}
