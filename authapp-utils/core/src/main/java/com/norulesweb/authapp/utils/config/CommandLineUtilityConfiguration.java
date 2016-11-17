package com.norulesweb.authapp.utils.config;

import com.norulesweb.authapp.core.common.AppRepositoryFactoryBean;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.jms.JmsAutoConfiguration;
import org.springframework.boot.orm.jpa.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.annotation.PropertySources;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * Basic configuration for a command-line utility.  This pulls in the core + eventing pieces and
 * sets up the JPA repositories.
 */
@Configuration
@PropertySources({
	@PropertySource(value = "classpath:spring-data-application.properties"),
	@PropertySource(value = "file:spring-data-application.runtime.properties", ignoreResourceNotFound = true)
})
@EnableAutoConfiguration(exclude={
	JmsAutoConfiguration.class
})
/* Define the packages to scan */
@ComponentScan(basePackages = {
	"com.norulesweb.authapp.core",
	"com.norulesweb.authapp.utils"
})
/* Set up JPA repositories */
@EnableTransactionManagement
@EnableJpaRepositories(
		repositoryFactoryBeanClass = AppRepositoryFactoryBean.class,
		basePackages = { "com.norulesweb.authapp.core.repository" }
)
@EntityScan(basePackages = { "com.norulesweb.authapp.core" })
public class CommandLineUtilityConfiguration {
}
