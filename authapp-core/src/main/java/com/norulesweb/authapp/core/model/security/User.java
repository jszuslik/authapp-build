package com.norulesweb.authapp.core.model.security;

import com.norulesweb.authapp.core.model.common.ModelBase;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.time.Instant;
import java.util.LinkedList;
import java.util.List;

@Entity
@Table(name = "USER")
@EntityListeners(AuditingEntityListener.class)
public class User extends ModelBase {

	private String username;

	private String password;

	private String firstname;

	private String lastname;

	private String email;

	private Boolean enabled;

	private Instant lastPasswordResetDate;

	private List<Authority> authorities;

	public User() { }

	public User(User user){
		super(user);
		setLastPasswordResetDate(user.getLastPasswordResetDate());
	}

	@Column(name = "USERNAME", length = 50, unique = true)
	@NotNull
	@Size(min = 4, max = 50)
	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	@Column(name = "PASSWORD", length = 100)
	@NotNull
	@Size(min = 4, max = 100)
	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	@Column(name = "FIRSTNAME", length = 50)
	@NotNull
	@Size(min = 4, max = 50)
	public String getFirstname() {
		return firstname;
	}

	public void setFirstname(String firstname) {
		this.firstname = firstname;
	}

	@Column(name = "LASTNAME", length = 50)
	@NotNull
	@Size(min = 4, max = 50)
	public String getLastname() {
		return lastname;
	}

	public void setLastname(String lastname) {
		this.lastname = lastname;
	}

	@Column(name = "EMAIL", length = 50)
	@NotNull
	@Size(min = 4, max = 50)
	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	@Column(name = "ENABLED")
	@NotNull
	public Boolean getEnabled() {
		return enabled;
	}

	public void setEnabled(Boolean enabled) {
		this.enabled = enabled;
	}

	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(
			name = "USER_AUTHORITY",
			joinColumns = {@JoinColumn(name = "USER_ID", referencedColumnName = "ID")},
			inverseJoinColumns = {@JoinColumn(name = "AUTHORITY_ID", referencedColumnName = "ID")})
	public List<Authority> getAuthorities() {
		return authorities;
	}
	public void setAuthorities(List<Authority> authorities) {
		this.authorities = authorities;
	}
	public void addAuthority(Authority authority){
		if(this.authorities == null){
			this.authorities = new LinkedList<>();
		}
		this.authorities.add(authority);
	}

	@CreatedDate
	@Column(name = "LASTPASSWORDRESETDATE")
	@NotNull
	public Instant getLastPasswordResetDate() {
		return lastPasswordResetDate;
	}

	public void setLastPasswordResetDate(Instant lastPasswordResetDate) {
		this.lastPasswordResetDate = lastPasswordResetDate;
	}
}
