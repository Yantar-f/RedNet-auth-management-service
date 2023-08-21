package com.rednet.authmanagementservice.repository.impl;

import com.rednet.authmanagementservice.entity.Registration;
import com.rednet.authmanagementservice.repository.RegistrationRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Component
public class RegistrationRepositoryImpl implements RegistrationRepository {
    private final RedisTemplate<String, Registration> template;
    private final long RegistrationExpirationMs;

    public RegistrationRepositoryImpl(
        @Qualifier("registrationRedisTemplate") RedisTemplate<String, Registration> template,
        @Value("${rednet.app.registration-expiration-ms}") long RegistrationExpirationMs
    ) {
        this.template = template;
        this.RegistrationExpirationMs = RegistrationExpirationMs;
    }

    public void save(String registrationID,  Registration registration) {
        template.opsForValue().set(registrationID, registration, RegistrationExpirationMs, TimeUnit.MILLISECONDS);
    }

    public Optional<Registration> find(String registrationID) {
        return Optional.ofNullable(template.opsForValue().get(registrationID));
    }

    public void delete(String registrationID) {
        template.opsForValue().getAndDelete(registrationID);
    }

    public List<Registration> findAll(String key) {
        return template.opsForList().range(key, 0, -1);
    }
}
