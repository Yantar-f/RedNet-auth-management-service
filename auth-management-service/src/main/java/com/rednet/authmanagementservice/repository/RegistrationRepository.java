package com.rednet.authmanagementservice.repository;

import com.rednet.authmanagementservice.entity.Registration;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

@Component
public interface RegistrationRepository {
    void                    save    (String registrationID,  Registration registration);

    Optional<Registration>  find    (String registrationID);

    void                    delete  (String registrationID);
}
