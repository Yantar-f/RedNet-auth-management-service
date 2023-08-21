package com.rednet.authmanagementservice.repository;

import com.rednet.authmanagementservice.entity.Registration;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Component
public interface RegistrationRepository {
    void save(String registrationID,  Registration registration);

    Optional<Registration> find(String registrationID);

    void delete(String registrationID);

    List<Registration> findAll(String key);
}
