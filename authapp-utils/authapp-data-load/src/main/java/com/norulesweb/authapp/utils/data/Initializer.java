package com.norulesweb.authapp.utils.data;

import com.norulesweb.authapp.core.model.security.Authority;
import com.norulesweb.authapp.core.model.security.AuthorityName;
import com.norulesweb.authapp.core.model.security.User;
import com.norulesweb.authapp.core.repository.security.AuthorityRepository;
import com.norulesweb.authapp.core.repository.security.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.annotation.PropertySources;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@PropertySources({
	@PropertySource(value = "classpath:initializer.properties"),
	@PropertySource(value = "file:initializer.runtime.properties", ignoreResourceNotFound = true)
})
@Transactional
public class Initializer {

	private static final Logger log = LoggerFactory.getLogger(Initializer.class);

	@Value("${initialize.user.name}")
	protected String userName;

	@Value("${initialize.user.password}")
	protected String userPassword;

	@Value("${initialize.user.firstname}")
	protected String userFirstName;

	@Value("${initialize.user.lastname}")
	protected String userLastName;

	@Value("${initialize.user.email}")
	protected String userEmail;

	@Value("${initialize.user.role.admin}")
	protected String adminRole;

	@Value("${initialize.user.role.user}")
	protected String userRole;

	@Value("${initialize.user.enabled}")
	protected Boolean enabled;

	@Value("${initialize.platform.name}")
	protected String platformName;

	@Value("${initialize.platform.description}")
	protected String platformDescription;

	@Autowired
	protected AuthorityRepository authorityRepository;

	@Autowired
	protected UserRepository userRepository;

	public void initializePlatform() {

		log.info("Start Initializing DB");

		initializeAuthorities();

		log.info("End Initializing DB");

	}
	 public void initializeAuthorities(){
		 PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

		 User user = new User();
		 user.setUsername(userName);
		 user.setPassword(passwordEncoder.encode(userPassword));
		 user.setFirstname(userFirstName);
		 user.setLastname(userLastName);
		 user.setEmail(userEmail);
		 user.setEnabled(enabled);

		 user = userRepository.save(user);

		 Authority adminAuth = new Authority();
		 adminAuth.setName(AuthorityName.ROLE_ADMIN);
		 adminAuth.addUser(user);
		 Authority adAuth = authorityRepository.save(adminAuth);

		 Authority userAuth = new Authority();
		 userAuth.setName(AuthorityName.ROLE_USER);
		 userAuth.addUser(user);
		 Authority usAuth = authorityRepository.save(userAuth);

		 user.addAuthority(adAuth);
		 user.addAuthority(usAuth);

		 user = userRepository.save(user);
	 }

}
