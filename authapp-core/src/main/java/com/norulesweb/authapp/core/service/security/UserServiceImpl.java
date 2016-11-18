package com.norulesweb.authapp.core.service.security;

import com.norulesweb.authapp.core.model.security.Authority;
import com.norulesweb.authapp.core.model.security.AuthorityName;
import com.norulesweb.authapp.core.model.security.User;
import com.norulesweb.authapp.core.repository.security.AuthorityRepository;
import com.norulesweb.authapp.core.repository.security.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class UserServiceImpl implements UserService {

	private static final Logger log = LoggerFactory.getLogger(UserService.class);

	@Autowired
	protected UserRepository userRepository;

	@Autowired
	protected AuthorityRepository authorityRepository;

	@Autowired
	protected AuthorityService authorityService;

	@Override
	public UserDTO createAppUser(UserDTO newUserDTO) {
		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

		String encodedPassword = passwordEncoder.encode(newUserDTO.getPassword());
		newUserDTO.setPassword(encodedPassword);

		User savedUser = userRepository.save(newUserDTO.buildModel());

		userRepository.flushAndRefresh(savedUser);

		return new UserDTO(savedUser);
	}

	@Override
	@Transactional(readOnly = true)
	public UserDTO findUserByUserId(String username){
		User user = userRepository.findByUsername(username);
		if (username.isEmpty()) {
			return null;
		} else {
			return new UserDTO(user);
		}
	}

	@Override
	public UserDTO addAdminAuth(UserDTO userDTO){
		Authority adAuth = authorityRepository.findByAuthorityName(AuthorityName.ROLE_ADMIN);
		User user = userRepository.findOne(userDTO.getId());
		adAuth.addUser(user);
		adAuth = authorityRepository.save(adAuth);
		user.addAuthority(adAuth);
		user = userRepository.save(user);

		userDTO = new UserDTO(user);

		return userDTO;
	}

	@Override
	public UserDTO addUserAuth(UserDTO userDTO) {
		Authority usAuth = authorityRepository.findByAuthorityName(AuthorityName.ROLE_USER);
		User user = userRepository.findOne(userDTO.getId());
		usAuth.addUser(user);
		usAuth = authorityRepository.save(usAuth);
		user.addAuthority(usAuth);
		user = userRepository.save(user);

		userDTO = new UserDTO(user);

		return userDTO;
	}

	@Override
	public UserDTO saveUserChanges(UserDTO userDTO) {
		User savedUser = userRepository.save(userDTO.buildModel());

		userRepository.flushAndRefresh(savedUser);

		return new UserDTO(savedUser);
	}
}
