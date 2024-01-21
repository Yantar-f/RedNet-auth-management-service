package com.rednet.authmanagementservice.client.fallbackfactory;

import com.rednet.authmanagementservice.client.RegistrationServiceClient;
import com.rednet.authmanagementservice.entity.Registration;
import com.rednet.authmanagementservice.exception.ServerErrorException;
import com.rednet.authmanagementservice.model.RegistrationCreationData;
import feign.FeignException;
import org.springframework.cloud.openfeign.FallbackFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@Component
public class RegistrationServiceClientFallbackFactory implements FallbackFactory<RegistrationServiceClient> {
    @Override
    public RegistrationServiceClient create(Throwable cause) {
        return new RegistrationServiceClient() {
            @Override
            public ResponseEntity<Registration> createRegistration(RegistrationCreationData data) {
                throw new ServerErrorException("Error during creating registration");
            }

            @Override
            public ResponseEntity<Registration> getRegistrationByID(String ID) {
                if (cause instanceof FeignException.NotFound exception) {
                    throw exception;
                } else {
                    throw new ServerErrorException("Error during finding registration");
                }
            }

            @Override
            public ResponseEntity<Void> updateRegistration(Registration registration) {
                if (cause instanceof FeignException.NotFound exception) {
                    throw exception;
                } else {
                    throw new ServerErrorException("Error during updating registration");
                }
            }

            @Override
            public ResponseEntity<Void> deleteRegistrationByID(String ID) {
                if (cause instanceof FeignException.NotFound exception) {
                    throw exception;
                } else {
                    throw new ServerErrorException("Error during deleting registration");
                }
            }
        };
    }
}
