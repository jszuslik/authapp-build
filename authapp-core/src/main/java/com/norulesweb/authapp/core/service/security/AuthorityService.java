package com.norulesweb.authapp.core.service.security;

import java.util.List;

public interface AuthorityService {
	AuthorityDTO findAuthorityByName(String name);
	List<AuthorityDTO> getAllAuthorities();
	AuthorityDTO saveAuthority(AuthorityDTO authorityDTO);
	List<AuthorityDTO> findByUser(UserDTO user);
}
