package com.norulesweb.authapp.api.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableWebSecurity
public class AuthAppWebSecurityConfiguration  extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
				// we don't need CSRF because our token is invulnerable
				.csrf().disable()

				// .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()

				// don't create session
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()

				.authorizeRequests()
				//.antMatchers(HttpMethod.OPTIONS, "/**").permitAll()

				// allow anonymous resource requests
				.antMatchers(
						HttpMethod.GET,
						"/",
						"/*.html",
						"/favicon.ico",
						"/**/*.html",
						"/**/*.css",
						"/**/*.js"
				).permitAll()
				.antMatchers("/auth/**").permitAll()
				.anyRequest().authenticated();

		// Custom JWT based security filter
//		httpSecurity
//				.addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);

		// disable page caching
		httpSecurity.headers().cacheControl();

	}

}
