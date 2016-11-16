package com.norulesweb.authapp.core.model.security;

import com.norulesweb.authapp.core.model.common.AuditableModelBase;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.List;

@Entity
@Table(name = "AUTHORITY")
public class Authority extends AuditableModelBase{

	private AuthorityName name;

	private List<User> users;

	public Authority() { }

	@Column(name = "NAME", length = 50)
	@NotNull
	@Enumerated(EnumType.STRING)
	public AuthorityName getName() {
		return name;
	}
	public void setName(AuthorityName name) {
		this.name = name;
	}

	@ManyToMany(mappedBy = "authorities", fetch = FetchType.LAZY)
	public List<User> getUsers() {
		return users;
	}
	public void setUsers(List<User> users) {
		this.users = users;
	}
}
