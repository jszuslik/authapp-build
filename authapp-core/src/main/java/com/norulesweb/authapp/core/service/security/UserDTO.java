package com.norulesweb.authapp.core.service.security;

import com.norulesweb.authapp.core.model.security.Authority;
import com.norulesweb.authapp.core.model.security.User;

import java.time.Instant;
import java.util.LinkedList;
import java.util.List;

public class UserDTO {

	protected Long id;

	private String username;

	private String password;

	private String firstname;

	private String lastname;

	private String email;

	private Boolean enabled;

	private Instant lastPasswordResetDate;

	private List<AuthorityDTO> authorities;

	public UserDTO() {}

	public UserDTO(User user) {
		if(user.getId() != null){
			setId(user.getId());
		}

		if(user.getUsername() != null) {
			setUsername(user.getUsername());
		}

		if(user.getPassword() != null){
			setPassword(user.getPassword());
		}

		if(user.getFirstname() != null){
			setFirstname(user.getFirstname());
		}

		if(user.getLastname() != null){
			setLastname(user.getLastname());
		}

		if(user.getEmail() != null){
			setEmail(user.getEmail());
		}

		if(user.getEnabled() != null){
			setEnabled(user.getEnabled());
		}

		if(user.getLastPasswordResetDate() != null){
			setLastPasswordResetDate(user.getLastPasswordResetDate());
		}

		if(user.getAuthorities() != null){
			authorities = new LinkedList<>();
			for(Authority authority : user.getAuthorities()){
				addAuthority(new AuthorityDTO(authority));
			}
		}
	}

	public User buildModel() {
		User user = new User();

		if(getId() != null){
			user.setId(getId());
		}

		if(getUsername() != null){
			user.setUsername(getUsername());
		}

		if(getPassword() != null){
			user.setPassword(getPassword());
		}

		if(getFirstname() != null){
			user.setFirstname(getFirstname());
		}

		if(getLastname() != null){
			user.setLastname(getLastname());
		}

		if(getEmail() != null){
			user.setEmail(getEmail());
		}

		if(getEnabled() != null){
			user.setEnabled(getEnabled());
		}

		if(getLastPasswordResetDate() != null){
			user.setLastPasswordResetDate(getLastPasswordResetDate());
		}

		if(getAuthorities() != null){
			List<Authority> authorities = new LinkedList<>();
			for(AuthorityDTO authorityDTO : getAuthorities()){
				Authority authority = authorityDTO.buildModel();
				authorities.add(authority);
			}
			user.setAuthorities(authorities);
		}

		return user;
	}

	public static UserDTO buildDTO(User user){
		if(user != null){
			return new UserDTO(user);
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

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getFirstname() {
		return firstname;
	}

	public void setFirstname(String firstname) {
		this.firstname = firstname;
	}

	public String getLastname() {
		return lastname;
	}

	public void setLastname(String lastname) {
		this.lastname = lastname;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public Boolean getEnabled() {
		return enabled;
	}

	public void setEnabled(Boolean enabled) {
		this.enabled = enabled;
	}

	public Instant getLastPasswordResetDate() {
		return lastPasswordResetDate;
	}

	public void setLastPasswordResetDate(Instant lastPasswordResetDate) {
		this.lastPasswordResetDate = lastPasswordResetDate;
	}

	public List<AuthorityDTO> getAuthorities() {
		return authorities;
	}

	public void setAuthorities(List<AuthorityDTO> authorities) {
		this.authorities = authorities;
	}

	public void addAuthority(AuthorityDTO authorityDTO){
		if(authorityDTO == null){
			this.authorities = new LinkedList<>();
		}
		this.authorities.add(authorityDTO);
	}
}
