package com.norulesweb.authapp.core.service.security;

import com.norulesweb.authapp.core.model.security.Authority;
import com.norulesweb.authapp.core.model.security.AuthorityName;
import com.norulesweb.authapp.core.model.security.User;
import com.norulesweb.authapp.core.repository.security.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.LinkedList;
import java.util.List;

public class AuthorityDTO {

	@Autowired
	protected UserRepository appUserRepository;

	protected Long id;

	protected String name;

	protected List<Long> users;

	public AuthorityDTO() { }

	public AuthorityDTO(Authority authority) {

		if(authority.getId() != null) {
			setId(authority.getId());
		}

		if(authority.getName() != null) {
			setName(authority.getName().name());
		}

		if(authority.getUsers() != null) {
			for(User user : authority.getUsers()){
				addUser(user.getId());
			}
		}
	}

	public Authority buildModel() {
		Authority authority = new Authority();

		if(getId() != null) {
			authority.setId(getId());
		}

		if(getName() != null){
			switch (getName()){
				case "ROLE_ADMIN":
					authority.setName(AuthorityName.ROLE_ADMIN);
					break;
				case "ROLE_USER":
					authority.setName(AuthorityName.ROLE_USER);
					break;
			}

		}

		if(getUsers() != null) {
			List<User> users = new LinkedList<>();
			for (Long userDTO : getUsers()){
				User user = appUserRepository.findOne(userDTO);
				users.add(user);
			}
			authority.setUsers(users);
		}

		return authority;
	}

	public static AuthorityDTO buildDTO(Authority authority) {
		if(authority != null){
			return new AuthorityDTO(authority);
		} else {
			return null;
		}
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public List<Long> getUsers() {
		return users;
	}

	public void setUsers(List<Long> users) {
		this.users= users;
	}

	public void addUser(Long userDTO){
		if(this.users == null){
			users = new LinkedList<>();
		}
		users.add(userDTO);
	}

}
