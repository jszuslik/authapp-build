package com.norulesweb.authapp.core.model.common;

import org.springframework.data.auditing.DateTimeProvider;

import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Calendar;
import java.util.GregorianCalendar;

/**
 * DateTimeProvider class to support Spring Data JPA auditing for
 * {@link org.springframework.data.annotation.CreatedDate} and
 * {@link org.springframework.data.annotation.LastModifiedDate} annotations
 * on models.
 */
public class AuditableDateTimeProvider implements DateTimeProvider {
    @Override
    public Calendar getNow() {
        return GregorianCalendar.from(ZonedDateTime.now(ZoneId.from(ZoneOffset.UTC)));
    }
}

