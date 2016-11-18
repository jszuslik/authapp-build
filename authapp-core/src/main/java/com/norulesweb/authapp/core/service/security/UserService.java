package com.norulesweb.authapp.core.service.security;

public interface UserService {
	UserDTO createAppUser(UserDTO userDTO);
	UserDTO findUserByUserId(String userId);
	UserDTO addAdminAuth(UserDTO userDTO);
	UserDTO addUserAuth(UserDTO userDTO);
	UserDTO saveUserChanges(UserDTO userDTO);
}
