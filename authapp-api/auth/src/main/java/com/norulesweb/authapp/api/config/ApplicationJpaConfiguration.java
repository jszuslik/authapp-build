package com.norulesweb.authapp.api.config;


import com.norulesweb.authapp.core.model.common.AuditableDateTimeProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@Configuration
@EnableJpaAuditing(
		dateTimeProviderRef = "dateTimeProvider"
)
public class ApplicationJpaConfiguration {

	/**
	 * The DateTimeProvider for auditable models
	 */
	@Bean
	public DateTimeProvider dateTimeProvider() {
		return new AuditableDateTimeProvider();
	}

}


