package com.rednet.authmanagementservice.repository;

import com.rednet.authmanagementservice.entity.Registration;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
public class RegistrationRepository {
    private final RedisTemplate<String, Registration> template;
    private final long RegistrationExpirationMs;

    public RegistrationRepository(
        @Qualifier("registrationRedisTemplate") RedisTemplate<String, Registration> template,
        @Value("${rednet.app.registration-expiration-ms}") long RegistrationExpirationMs
    ) {
        this.template = template;
        this.RegistrationExpirationMs = RegistrationExpirationMs;
    }

    public void save(String registrationID,  Registration registration) {
        template.opsForValue().set(registrationID, registration, RegistrationExpirationMs, TimeUnit.MILLISECONDS);
    }

    public Registration find(String registrationID) {
        return template.opsForValue().get(registrationID);
    }
}
