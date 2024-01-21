package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.client.RegistrationServiceClient;
import com.rednet.authmanagementservice.entity.Registration;
import com.rednet.authmanagementservice.exception.RegistrationNotFoundException;
import com.rednet.authmanagementservice.exception.ServerErrorException;
import com.rednet.authmanagementservice.model.RegistrationCreationData;
import com.rednet.authmanagementservice.service.RegistrationService;
import feign.FeignException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class RegistrationServiceImpl implements RegistrationService {
    private final RegistrationServiceClient serviceClient;

    public RegistrationServiceImpl(RegistrationServiceClient serviceClient) {
        this.serviceClient = serviceClient;
    }

    @Override
    public Registration createRegistration(RegistrationCreationData data) {
        Registration registration = serviceClient.createRegistration(data).getBody();

        return Optional
                .ofNullable(registration)
                .orElseThrow(() -> new ServerErrorException("Error during creating registration"));
    }

    @Override
    public Optional<Registration> findRegistrationByID(String ID) {
        try {
            Registration registration = serviceClient.getRegistrationByID(ID).getBody();

            return Optional.of(Optional
                    .ofNullable(registration)
                    .orElseThrow(() -> new ServerErrorException("Error during getting registration " + ID)));
        } catch (FeignException.NotFound e) {
            return Optional.empty();
        }
    }

    @Override
    public void updateRegistration(Registration registration) {
        try {
            serviceClient.updateRegistration(registration);
        } catch (FeignException.NotFound e) {
            throw new RegistrationNotFoundException(registration.getID());
        }
    }

    @Override
    public void deleteRegistrationByID(String ID) {
        try {
            serviceClient.deleteRegistrationByID(ID);
        } catch (FeignException.NotFound e) {
            throw new RegistrationNotFoundException(ID);
        }
    }
}
