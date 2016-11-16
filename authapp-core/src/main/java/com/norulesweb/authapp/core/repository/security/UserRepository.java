package com.norulesweb.authapp.core.repository.security;

import com.norulesweb.authapp.core.common.AppRepository;
import com.norulesweb.authapp.core.model.security.User;

public interface UserRepository extends AppRepository<User, Long> {
	User findByUsername(String username);
}
