package com.norulesweb.authapp.core.service.security;

import com.norulesweb.authapp.core.model.security.Authority;
import com.norulesweb.authapp.core.model.security.AuthorityName;
import com.norulesweb.authapp.core.repository.security.AuthorityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

import static com.norulesweb.authapp.core.model.security.AuthorityName.ROLE_ADMIN;
import static com.norulesweb.authapp.core.model.security.AuthorityName.ROLE_USER;

@Service
@Transactional
public class AuthorityServiceImpl implements AuthorityService {

	@Autowired
	protected AuthorityRepository authorityRepository;

	@Override
	public AuthorityDTO findAuthorityByName(String name){
		Authority authority;
		AuthorityName authorityName = AuthorityName.valueOf(name);
		switch (authorityName){
			case ROLE_ADMIN:
				authority = authorityRepository.findByAuthorityName(ROLE_ADMIN);
				break;
			case ROLE_USER:
				authority = authorityRepository.findByAuthorityName(ROLE_USER);
				break;
			default:
				authority = null;
				break;
		}
		if(authority != null) {
			return new AuthorityDTO(authority);
		}
		return null;
	}

	@Override
	public List<AuthorityDTO> getAllAuthorities() {
		List<Authority> authorities = authorityRepository.findAll();
		List<AuthorityDTO> authorityDTOs = new ArrayList<>();
		for(Authority authority : authorities){
			AuthorityDTO authorityDTO = new AuthorityDTO(authority);
			authorityDTOs.add(authorityDTO);
		}
		return authorityDTOs;
	}

	@Override
	public AuthorityDTO saveAuthority(AuthorityDTO authorityDTO){
		Authority savedAuthority = authorityRepository.save(authorityDTO.buildModel());
		authorityRepository.flushAndRefresh(savedAuthority);
		return new AuthorityDTO(savedAuthority);
	}

	@Override
	public List<AuthorityDTO> findByUser(UserDTO currentUser) {
		List<AuthorityDTO> authorities = currentUser.getAuthorities();
		List<AuthorityDTO> userAuths = new ArrayList<>();
		for(AuthorityDTO authority : authorities){
			for(Long user : authority.getUsers()){
				if(user == currentUser.getId()){
					userAuths.add(authority);
				}
			}
		}
		return userAuths;
	}
}
