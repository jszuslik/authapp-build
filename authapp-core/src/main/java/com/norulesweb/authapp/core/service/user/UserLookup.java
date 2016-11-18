package com.norulesweb.authapp.core.service.user;

import org.springframework.security.core.userdetails.UserDetails;

public interface UserLookup {
	UserDetails getCurrentUser();
}
