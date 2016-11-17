package com.norulesweb.authapp.utils.config;

import com.norulesweb.authapp.core.model.common.AuditableDateTimeProvider;
import org.springframework.beans.factory.annotation.Value;
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
	 * The StudentTrackerUser ID that the utility will run under (for auditing purposes)
	 */
	@Value("${initialize.user.name}")
	protected String utilitiesUserName;

	/**
	 * The DateTimeProvider for auditable models
	 */
	@Bean
	public DateTimeProvider dateTimeProvider() {
		return new AuditableDateTimeProvider();
	}

}
