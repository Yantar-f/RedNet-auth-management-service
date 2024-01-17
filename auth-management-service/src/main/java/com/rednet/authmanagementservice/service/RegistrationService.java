package com.rednet.authmanagementservice.service;

import com.rednet.authmanagementservice.entity.Registration;
import com.rednet.authmanagementservice.model.RegistrationData;

import java.util.Optional;

public interface RegistrationService {
    Registration            createRegistration      (RegistrationData registrationData);
    Optional<Registration>  findRegistrationByID    (String ID);

    void updateRegistration     (Registration registration);
    void deleteRegistrationByID (String ID);
}
