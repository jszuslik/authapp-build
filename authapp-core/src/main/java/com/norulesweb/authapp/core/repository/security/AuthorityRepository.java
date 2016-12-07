package com.norulesweb.authapp.core.repository.security;

import com.norulesweb.authapp.core.common.AppRepository;
import com.norulesweb.authapp.core.model.security.Authority;
import com.norulesweb.authapp.core.model.security.AuthorityName;

import java.util.List;

public interface AuthorityRepository extends AppRepository<Authority, Long>{
	Authority findByName(AuthorityName name);
	List<Authority> findAll();
}
