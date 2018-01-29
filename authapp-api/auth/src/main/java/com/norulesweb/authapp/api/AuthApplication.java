package com.norulesweb.authapp.api;

import com.norulesweb.authapp.core.common.AppRepositoryFactoryBean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jms.JmsAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.boot.context.web.ErrorPageFilter;
import org.springframework.boot.context.web.SpringBootServletInitializer;
import org.springframework.boot.orm.jpa.EntityScan;
import org.springframework.context.annotation.*;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@SpringBootApplication
@PropertySources({
		                 @PropertySource(value = "classpath:actuator.properties"),
		                 @PropertySource(value = "classpath:spring-data-application.properties", ignoreResourceNotFound = true),
		                 @PropertySource(value = "classpath:spring-data-application.runtime.properties", ignoreResourceNotFound = true)
})
@ComponentScan(
		basePackages = {
				               "com.norulesweb.authapp.core",
				               "com.norulesweb.authapp.api"
		}
)
@EnableAutoConfiguration(exclude={
		                                 JmsAutoConfiguration.class
})
@ImportResource("classpath:auth/auth-integration.xml")
@EnableTransactionManagement
@EnableJpaRepositories(
		repositoryFactoryBeanClass = AppRepositoryFactoryBean.class,
		basePackages = { "com.norulesweb.authapp.core.repository" }
)
@EntityScan(basePackages = { "com.norulesweb.authapp.core.model" })
public class AuthApplication extends SpringBootServletInitializer {
	private static final Logger log = LoggerFactory.getLogger(AuthApplication.class);

	@Override
	protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
		return application.sources(AuthApplication.class);
	}

	public static void main(String[] args) {
		SpringApplication.run(AuthApplication.class, args);
	}

}
